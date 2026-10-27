//go:build windows

package web_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A policy made in the console, assigned to a customer: the device page
// shows where each part comes from, a missing required program is installed
// once (not again while it is retried later), a device policy overrides the
// customer's, and removing assignments falls back to the server settings.
func TestPolicies(t *testing.T) {
	e := newEnv(t)
	e.useRealClock()
	e.srv.DataDir = t.TempDir()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	d, stop := startAgent(t, e)
	defer stop()
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()

	// A library package that "installs" by exiting 0.
	exe, err := os.ReadFile(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"))
	if err != nil {
		t.Skip("no cmd.exe")
	}
	r := uploadSoftware(t, e, admin, "tool.exe", exe, "name", "Tool", "args", "/c exit 0")
	pkg := strings.TrimPrefix(r.loc, "/software/")
	if _, err := strconv.Atoi(pkg); err != nil {
		t.Fatalf("upload: %s", r.loc)
	}

	form := url.Values{"name": {"Office"}, "updates_set": {"1"}, "mode": {"security"}, "day": {"2"}, "hour": {"4"},
		"software_set": {"1"}, "req_source": {"library", "winget"}, "req_id": {pkg, ""}, "req_match": {"Tool for tests", ""},
		"alerts_set": {"1"}, "cpu_percent": {"75"}, "cpu_minutes": {"10"}, "mem_percent": {"90"}, "mem_minutes": {"15"},
		"disk_percent": {"90"}, "disk_min_free_gb": {"5"}, "offline_minutes": {"20"}, "reboot_days": {"7"}, "watch_services": {"Spooler"}}
	r = admin.do(http.MethodPost, "/policies/new", form, nil)
	m := regexp.MustCompile(`^/policies/(\d+)$`).FindStringSubmatch(r.loc)
	if m == nil {
		t.Fatalf("new policy: %d %s", r.code, r.loc)
	}
	pid := m[1]
	if r := admin.post("/policies/new", "name", "Office"); !strings.Contains(r.loc, "/policies/new") {
		t.Fatal("duplicate name accepted")
	}
	if r := admin.post("/policies/"+pid+"/assign", "target", "customer:"+itoa(d.CustomerID)); r.code != http.StatusSeeOther {
		t.Fatalf("assign: %d", r.code)
	}
	base := "/devices/" + itoa(d.ID)
	page := admin.get(base + "/policy").body
	if strings.Count(page, `href="/policies/`+pid+`"`) != 3 || !strings.Contains(page, "assigned to the customer") || !strings.Contains(page, "missing") {
		t.Fatal("device policy page")
	}

	// Without an inventory nothing is installed blindly.
	e.srv.RunRequiredSoftware(ctx)
	if strings.Contains(admin.get(base+"/activity").body, "install Tool") {
		t.Fatal("installed without an inventory")
	}
	admin.post(base + "/refresh")
	waitFor(t, "inventory", func() bool {
		dd, err := e.st.Device(ctx, d.ID)
		return err == nil && dd.Inventory != nil
	})
	// The missing program is installed as a job, and not started twice.
	e.srv.RunRequiredSoftware(ctx)
	e.srv.RunRequiredSoftware(ctx)
	waitForUpTo(t, "policy installation", 60*time.Second, func() bool {
		b := admin.get(base + "/activity").body
		return strings.Count(b, "install Tool") == 1 && !strings.Contains(b, "data-autorefresh")
	})
	if !strings.Contains(admin.get("/audit?q=policy.install").body, "required program") {
		t.Fatal("audit of the policy installation")
	}
	if !strings.Contains(admin.get(base+"/policy").body, "installation started") {
		t.Fatal("device page does not show the attempt")
	}

	// A device policy without parts: everything still comes from the customer.
	r = admin.do(http.MethodPost, "/policies/new", url.Values{"name": {"Empty"}}, nil)
	empty := strings.TrimPrefix(r.loc, "/policies/")
	if r := admin.post(base+"/policy", "policy", empty); r.code != http.StatusSeeOther {
		t.Fatalf("device policy: %d", r.code)
	}
	if b := admin.get(base + "/policy").body; strings.Count(b, `href="/policies/`+pid+`"`) != 3 {
		t.Fatal("parts not set by the device policy must come from the customer")
	}
	// Deleting the customer's policy: the server settings apply.
	if r := admin.post("/policies/" + pid + "/delete"); r.code != http.StatusSeeOther {
		t.Fatalf("delete: %d", r.code)
	}
	if b := admin.get(base + "/policy").body; strings.Count(b, "server settings") != 4 {
		t.Fatal("fallback to the server settings")
	}
	if b := admin.get("/policies").body; !strings.Contains(b, "Empty") || strings.Contains(b, ">Office<") {
		t.Fatal("policy list")
	}
}

// A policy automation due now starts one job for the policy's devices, once
// per time slot.
func TestPolicyAutomations(t *testing.T) {
	e := newEnv(t)
	e.useRealClock()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	d, stop := startAgent(t, e)
	defer stop()
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()

	r := admin.post("/scripts/new", "name", "Nightly", "shell", "cmd", "timeout", "60", "script", "echo nightly")
	sid := strings.TrimPrefix(r.loc, "/scripts/")
	now := time.Now()
	r = admin.do(http.MethodPost, "/policies/new", url.Values{"name": {"Auto"}, "automations_set": {"1"},
		"auto_script": {sid, ""}, "auto_time": {now.Format("15:04"), "22:00"}, "auto_day_0": {strconv.Itoa(int(now.Weekday()))}}, nil)
	pid := strings.TrimPrefix(r.loc, "/policies/")
	if _, err := strconv.Atoi(pid); err != nil {
		t.Fatalf("new policy: %s", r.loc)
	}
	admin.post("/devices/"+itoa(d.ID)+"/policy", "policy", pid)
	e.srv.RunPolicyAutomations(ctx)
	e.srv.RunPolicyAutomations(ctx)
	jobs, err := e.st.Jobs(ctx, "", 0, 10)
	if err != nil || len(jobs) != 1 || jobs[0].CreatedBy != "policy Auto" || jobs[0].Total != 1 {
		t.Fatalf("jobs: %+v %v", jobs, err)
	}
	waitForUpTo(t, "automation run", 30*time.Second, func() bool {
		j, err := e.st.Job(ctx, jobs[0].ID)
		return err == nil && j.Done == 1
	})
}
