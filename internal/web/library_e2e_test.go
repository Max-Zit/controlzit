package web_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

var jobLocRE = regexp.MustCompile(`^/jobs/(\d+)$`)

func TestScriptLibraryAndJobs(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the agent runs cmd scripts")
	}
	e := newEnv(t)
	e.now = time.Now()
	e.srv.SetClock(time.Now)
	e.st.SetClock(time.Now)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	d, stop := startAgent(t, e)
	defer stop()
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()

	// A second device that is offline (enrolled, no agent running).
	other, _ := e.st.CreateCustomer(ctx, "Other Ltd", "")
	osite, _ := e.st.CreateSite(ctx, other, "Branch", "", "")
	tok, _ := e.st.CreateEnrollToken(ctx, osite, "", "admin", time.Hour, 1)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	off, err := e.st.EnrollDevice(ctx, tok, pub, "OFFLINE-PC", "Windows", "0.2.11", "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}

	// The library: create, refuse a duplicate name.
	r := admin.post("/scripts/new", "name", "Say hello", "shell", "cmd", "timeout", "60", "script", "echo job-ok %COMPUTERNAME%", "description", "test")
	if r.code != http.StatusSeeOther || !strings.HasPrefix(r.loc, "/scripts/") {
		t.Fatalf("create: %d %s", r.code, r.loc)
	}
	sid := strings.TrimPrefix(r.loc, "/scripts/")
	admin.post("/scripts/new", "name", "Say hello", "shell", "cmd", "timeout", "60", "script", "ver")
	if !strings.Contains(admin.get("/scripts/new").body, "already exists") {
		t.Fatal("duplicate name accepted")
	}
	if r := admin.get("/scripts"); !strings.Contains(r.body, "Say hello") {
		t.Fatal("library list")
	}

	// A job on both devices: the online one runs now, the offline one waits.
	r = admin.post("/scripts/"+sid+"/run", "device", itoa(d.ID), "device", itoa(off.ID))
	m := jobLocRE.FindStringSubmatch(r.loc)
	if r.code != http.StatusSeeOther || m == nil {
		t.Fatalf("run: %d %s", r.code, r.loc)
	}
	job := r.loc
	waitFor(t, "job run", func() bool { return strings.Contains(admin.get(job).body, `badge ok"><i></i>succeeded`) })
	r = admin.get(job)
	if !strings.Contains(r.body, "OFFLINE-PC") || !strings.Contains(r.body, ">waiting<") || !strings.Contains(r.body, "data-autorefresh") {
		t.Fatal("offline device should wait")
	}
	runLink := regexp.MustCompile(`href="(/devices/\d+/scripts/\d+)"`).FindStringSubmatch(r.body)
	if runLink == nil || !strings.Contains(admin.get(runLink[1]).body, "job-ok") {
		t.Fatal("job output not stored")
	}
	if !strings.Contains(admin.get("/audit?q=job").body, "job #"+m[1]) {
		t.Fatal("job run not audited")
	}

	// A schedule for all devices at the current minute creates one job.
	now := time.Now()
	if r := admin.post("/scripts/"+sid+"/schedules", "day", strconv.Itoa(int(now.Weekday())), "time", now.Format("15:04"), "all", "1"); r.code != http.StatusSeeOther {
		t.Fatalf("schedule: %d", r.code)
	}
	e.srv.RunSchedules(ctx)
	e.srv.RunSchedules(ctx)
	r = admin.get("/scripts/" + sid)
	if n := strings.Count(r.body, `<a href="/jobs/`); n != 4 { // two jobs, two links each
		t.Fatalf("schedule created %d job links, want 4", n)
	}
	if !strings.Contains(admin.get("/scripts").body, "Pause") {
		t.Fatal("schedule not listed")
	}

	// The device page loads a library script into the form.
	if r := admin.get("/devices/" + itoa(d.ID) + "/scripts?lib=" + sid); !strings.Contains(r.body, "echo job-ok %COMPUTERNAME%</textarea>") {
		t.Fatal("library script not loaded on the device page")
	}

	// A technician of the other customer runs library scripts only there and
	// cannot change the library.
	admin.post("/users", "username", "tech", "password", "tech password 123", "role", "technician", "customers", itoa(other))
	tc := e.client("192.168.1.40")
	tc.post("/login", "username", "tech", "password", "tech password 123")
	sec := secretRE.FindStringSubmatch(tc.get("/login/enroll").body)[1]
	tc.post("/login/enroll", "code", e.code(sec))
	tc.post("/account/password", "current", "tech password 123", "password", "tech password 1234", "password2", "tech password 1234")
	if r := tc.get("/scripts"); r.code != http.StatusOK || !strings.Contains(r.body, "Say hello") || strings.Contains(r.body, "/jobs/"+m[1]) {
		t.Fatalf("technician library: %d", r.code)
	}
	if r := tc.post("/scripts/new", "name", "x", "shell", "cmd", "timeout", "60", "script", "ver"); r.code != http.StatusForbidden {
		t.Errorf("technician created a library script: %d", r.code)
	}
	if r := tc.post("/scripts/"+sid, "name", "x", "shell", "cmd", "timeout", "60", "script", "ver"); r.code != http.StatusForbidden {
		t.Errorf("technician edited a library script: %d", r.code)
	}
	if r := tc.post("/scripts/"+sid+"/run", "device", itoa(d.ID)); r.loc != "/scripts/"+sid+"/run" {
		t.Errorf("technician ran a script on another customer's device: %s", r.loc)
	}
	if r := tc.post("/scripts/"+sid+"/run", "all", "1"); r.loc != "/scripts/"+sid+"/run" && !strings.HasPrefix(r.loc, "/jobs/") {
		t.Errorf("technician all devices: %s", r.loc)
	} else if strings.HasPrefix(r.loc, "/jobs/") && strings.Contains(tc.get(r.loc).body, d.Hostname) {
		t.Error("technician job reached a device of another customer")
	}
	if r := tc.get(job); r.code != http.StatusNotFound {
		t.Errorf("technician opened the admin's job: %d", r.code)
	}
}
