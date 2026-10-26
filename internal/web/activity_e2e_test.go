//go:build windows

package web_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Tasks of a device: a long script runs, a second one waits behind it and
// is cancelled while waiting, the first is stopped while it runs; a task
// for an offline device waits for it.
func TestDeviceActivity(t *testing.T) {
	e := newEnv(t)
	e.useRealClock()
	e.srv.TaskWait = 500 * time.Millisecond
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	d, stop := startAgent(t, e)
	admin, _ := e.setupAdmin("192.168.1.10")
	base := "/devices/" + itoa(d.ID)
	cancelRE := regexp.MustCompile(`action="` + base + `/activity/(\d+)/cancel"`)

	// A quick script still shows its result at once.
	if r := admin.post(base+"/scripts", "shell", "cmd", "timeout", "60", "script", "echo quick"); !strings.Contains(r.loc, base+"/scripts/") {
		t.Fatalf("quick script: %d %s", r.code, r.loc)
	}

	r := admin.post(base+"/scripts", "shell", "powershell", "timeout", "300", "script", "Start-Sleep -Seconds 120; 'late'")
	if r.code != http.StatusSeeOther || r.loc != base+"/activity" {
		t.Fatalf("long script: %d %s", r.code, r.loc)
	}
	var page string
	waitFor(t, "running task", func() bool {
		page = admin.get(base + "/activity").body
		return strings.Contains(page, "badge warn") && strings.Contains(page, "data-autorefresh")
	})
	first := cancelRE.FindStringSubmatch(page)
	if first == nil {
		t.Fatal("no stop button")
	}
	// The second script waits behind the first.
	admin.post(base+"/scripts", "shell", "cmd", "timeout", "60", "script", "echo second")
	page = admin.get(base + "/activity").body
	ids := cancelRE.FindAllStringSubmatch(page, -1)
	if len(ids) != 2 || !strings.Contains(page, ">waiting<") {
		t.Fatalf("waiting task: %d buttons", len(ids))
	}
	second := ids[0][1] // newest first
	if second == first[1] {
		second = ids[1][1]
	}
	if r := admin.post(base + "/activity/" + second + "/cancel"); r.code != http.StatusSeeOther {
		t.Fatalf("cancel waiting: %d", r.code)
	}
	// Stopping the running script ends it long before its two minutes.
	start := time.Now()
	if r := admin.post(base + "/activity/" + first[1] + "/cancel"); r.code != http.StatusSeeOther {
		t.Fatalf("stop running: %d", r.code)
	}
	waitFor(t, "stopped task", func() bool {
		page = admin.get(base + "/activity").body
		return !strings.Contains(page, "data-autorefresh")
	})
	if time.Since(start) > 30*time.Second || strings.Count(page, ">cancelled<") != 2 || !strings.Contains(page, "stopped from the console") {
		t.Fatal("history after cancelling")
	}
	if !strings.Contains(admin.get("/audit?q=task.cancel").body, "stopped running task") {
		t.Fatal("audit of the stop")
	}

	// Offline: the task waits.
	stop()
	waitFor(t, "device offline", func() bool { return !e.srv.Connected(d.ID) })
	r = admin.post(base+"/scripts", "shell", "cmd", "timeout", "60", "script", "echo later")
	if r.loc != base+"/activity" {
		t.Fatalf("offline script: %s", r.loc)
	}
	page = admin.get(base + "/activity").body
	if !strings.Contains(page, ">waiting<") || len(cancelRE.FindAllStringSubmatch(page, -1)) != 1 {
		t.Fatal("offline task is not waiting")
	}
}
