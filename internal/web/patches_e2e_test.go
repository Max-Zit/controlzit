package web_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/max-zit/rmmzit/internal/agent"
	"github.com/max-zit/rmmzit/internal/proto"
)

const (
	secID   = "11111111-2222-3333-4444-555555555555"
	otherID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	upgID   = "99999999-8888-7777-6666-555555555555"
)

func TestWindowsUpdates(t *testing.T) {
	e := newEnv(t)
	e.useRealClock()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key

	var mu sync.Mutex
	installed := map[string]bool{}
	var installs [][]string
	agent.PatchScan = func(context.Context) (*agent.PatchScanResult, error) {
		mu.Lock()
		defer mu.Unlock()
		r := &agent.PatchScanResult{History: []proto.PatchHistoryItem{{Title: "Old update KB1", Date: time.Now().Add(-48 * time.Hour), Result: 2}}}
		for _, u := range []proto.PatchUpdate{
			{ID: secID, Title: "2026-10 Cumulative Update (KB5099999)", Severity: "Critical", Categories: []string{"Security Updates"}, Size: 400 << 20, Reboot: true},
			{ID: otherID, Title: "Feature on demand <b>tool</b>", Categories: []string{"Updates"}, Size: 1 << 20},
			{ID: upgID, Title: "Windows 12 upgrade", Categories: []string{"Upgrades"}},
		} {
			if !installed[u.ID] {
				r.Updates = append(r.Updates, u)
			}
		}
		return r, nil
	}
	agent.PatchInstall = func(_ context.Context, ids []string) (*agent.PatchInstallResult, error) {
		mu.Lock()
		defer mu.Unlock()
		installs = append(installs, ids)
		res := &agent.PatchInstallResult{Result: 2, RebootRequired: true}
		for _, id := range ids {
			installed[id] = true
			res.Results = append(res.Results, proto.PatchResult{ID: id, Title: "update " + id[:4], Result: 2})
		}
		return res, nil
	}
	d, stop := startAgent(t, e)
	defer stop()
	admin, _ := e.setupAdmin("192.168.1.10")
	base := "/devices/" + itoa(d.ID) + "/updates"

	if r := admin.get(base); r.code != http.StatusOK || !strings.Contains(r.body, "has not reported Windows updates") {
		t.Fatalf("updates page before a report: %d", r.code)
	}
	if r := admin.post(base + "/scan"); r.code != http.StatusSeeOther {
		t.Fatalf("scan: %d", r.code)
	}
	waitFor(t, "patch report", func() bool { return strings.Contains(admin.get(base).body, "KB5099999") })
	r := admin.get(base)
	if strings.Contains(r.body, "<b>tool</b>") || !strings.Contains(r.body, "Windows 12 upgrade") || !strings.Contains(r.body, "Old update KB1") {
		t.Fatal("updates page content")
	}
	if !strings.Contains(r.body, `value="`+secID+`" checked`) || strings.Contains(r.body, `value="`+upgID+`" checked`) {
		t.Fatal("security updates should be preselected, upgrades not")
	}

	// Unknown IDs are ignored; known ones go to the agent.
	if r := admin.post(base+"/install", "id", "00000000-0000-0000-0000-000000000000"); r.code != http.StatusSeeOther {
		t.Fatalf("install unknown: %d", r.code)
	}
	if !strings.Contains(admin.get(base).body, "Choose at least one update.") {
		t.Fatal("unknown update accepted")
	}
	admin.post(base+"/install", "id", otherID)
	waitFor(t, "installation result", func() bool { return strings.Contains(admin.get("/audit?q=patch.result").body, "1 installed, 0 failed") })
	// The agent reports the installation, then the new search.
	waitFor(t, "updated list", func() bool {
		r = admin.get(base)
		return strings.Contains(r.body, "Last installation") && !strings.Contains(r.body, `value="`+otherID+`"`) && strings.Contains(r.body, "restart required")
	})
	if !strings.Contains(admin.get("/audit?q=patch.install").body, "install 1 Windows updates") {
		t.Fatal("install not audited")
	}

	// Overview of all devices.
	r = admin.get("/updates?show=security")
	if r.code != http.StatusOK || !strings.Contains(r.body, d.Hostname) {
		t.Fatalf("overview: %d", r.code)
	}

	// Automatic installation of security updates on today's schedule.
	now := time.Now()
	pid := customerPolicy(t, admin, d.CustomerID, "name", "Updates", "updates_set", "1", "mode", "security", "day", strconv.Itoa(int(now.Weekday())), "hour", strconv.Itoa(now.Hour()))
	if !strings.Contains(admin.get("/policies/"+pid).body, `value="security" checked`) {
		t.Fatal("policy not saved")
	}
	e.srv.RunPatchSchedule(context.Background())
	waitFor(t, "automatic installation", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(installs) == 2
	})
	mu.Lock()
	if len(installs[1]) != 1 || installs[1][0] != secID {
		t.Fatalf("automatic installation chose %v", installs[1])
	}
	mu.Unlock()
	waitFor(t, "idle after automatic installation", func() bool { return !strings.Contains(admin.get(base).body, "Installing") })
	e.srv.RunPatchSchedule(context.Background()) // once a day
	time.Sleep(500 * time.Millisecond)
	mu.Lock()
	if len(installs) != 2 {
		t.Fatal("automatic installation ran twice on one day")
	}
	mu.Unlock()
	if r := admin.post("/policies/"+pid, "name", "Updates", "updates_set", "1", "mode", "security", "hour", "3"); !strings.Contains(r.body+admin.get(r.loc).body, "Choose at least one day.") {
		t.Fatal("policy without days accepted")
	}

	// Read-only users see the updates but cannot start anything.
	admin.post("/users", "username", "viewer", "password", "viewer password 1", "role", "readonly", "all_customers", "1")
	v := e.client("192.168.1.31")
	v.post("/login", "username", "viewer", "password", "viewer password 1")
	sec := secretRE.FindStringSubmatch(v.get("/login/enroll").body)[1]
	v.post("/login/enroll", "code", e.code(sec))
	v.post("/account/password", "current", "viewer password 1", "password", "viewer password 22", "password2", "viewer password 22")
	if r := v.get(base); r.code != http.StatusOK || strings.Contains(r.body, "Install selected") {
		t.Errorf("read-only updates page: %d", r.code)
	}
	for _, p := range []string{base + "/scan", base + "/install"} {
		if r := v.post(p, "id", secID); r.code != http.StatusForbidden {
			t.Errorf("read-only user posted to %s: %d", p, r.code)
		}
	}
	if r := v.get("/policies/" + pid); r.code != http.StatusForbidden {
		t.Errorf("read-only user opened the update policy: %d", r.code)
	}
}
