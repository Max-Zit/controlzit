package web_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"html"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRemoteActions(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the agent actions are Windows only")
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
	base := "/devices/" + itoa(d.ID)

	// Services: the list, a filter, and the agent refusing to stop itself.
	r := admin.get(base + "/services")
	if r.code != http.StatusOK || !strings.Contains(r.body, "EventLog") {
		t.Fatalf("services: %d", r.code)
	}
	r = admin.get(base + "/services?q=eventlog&state=running")
	if !strings.Contains(r.body, "EventLog") || strings.Contains(r.body, "Spooler</code>") {
		t.Fatal("service filter")
	}
	if r := admin.post(base+"/services", "name", "ControlZitAgent", "action", "stop"); r.code != http.StatusSeeOther {
		t.Fatalf("service control: %d", r.code)
	}
	if r := admin.get(base + "/services"); !strings.Contains(r.body, "cannot stop itself") {
		t.Fatal("stopping the agent's own service was not refused")
	}
	if r := admin.post(base+"/services", "name", "x", "action", "delete"); r.code != http.StatusSeeOther {
		t.Fatalf("unknown service action: %d", r.code)
	}

	// Processes: list, then end a process started for the test.
	p := exec.Command(filepath.Join(windowsDir(), "System32", "PING.EXE"), "-n", "120", "127.0.0.1")
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- p.Wait() }()
	pid := strconv.Itoa(p.Process.Pid)
	r = admin.get(base + "/processes?q=" + pid)
	if r.code != http.StatusOK || !strings.Contains(strings.ToLower(r.body), "ping.exe") {
		t.Fatalf("processes: %d", r.code)
	}
	if r := admin.post(base+"/processes/kill", "pid", pid, "name", "notping.exe"); r.code != http.StatusSeeOther {
		t.Fatalf("kill: %d", r.code)
	}
	if r := admin.get(base + "/processes"); !strings.Contains(r.body, "the process has changed") {
		t.Fatal("a kill with the wrong name was not refused")
	}
	admin.post(base+"/processes/kill", "pid", pid, "name", "PING.EXE")
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		p.Process.Kill()
		t.Fatal("the process was not ended")
	}

	// Scripts: output on the page, in the history and in the audit log.
	r = admin.post(base+"/scripts", "shell", "powershell", "timeout", "60", "script", "Write-Output \"hello <from> $env:COMPUTERNAME\"\nexit 2")
	if r.code != http.StatusSeeOther || !strings.HasPrefix(r.loc, base+"/scripts/") {
		t.Fatalf("script run: %d %s", r.code, r.loc)
	}
	run := admin.get(r.loc)
	if run.code != http.StatusOK || !strings.Contains(run.body, html.EscapeString("hello <from>")) || !strings.Contains(run.body, "exit code 2") {
		t.Fatalf("script result page: %d", run.code)
	}
	if strings.Contains(run.body, "hello <from>") {
		t.Fatal("script output not escaped")
	}
	r = admin.post(base+"/scripts", "shell", "cmd", "timeout", "30", "script", "echo cmd says hi")
	if run := admin.get(r.loc); !strings.Contains(run.body, "cmd says hi") || !strings.Contains(run.body, "exit code 0") {
		t.Fatal("cmd script")
	}
	if r := admin.get(base + "/scripts"); !strings.Contains(r.body, "Recent runs") || strings.Count(r.body, base+"/scripts/") < 4 {
		t.Fatal("script history")
	}
	if r := admin.post(base+"/scripts", "shell", "zsh", "timeout", "30", "script", "ls"); r.code != http.StatusSeeOther || r.loc != base+"/scripts" {
		t.Fatalf("unknown shell: %d %s", r.code, r.loc)
	}
	if r := admin.post(base+"/scripts", "shell", "cmd", "timeout", "9999", "script", "ver"); r.loc != base+"/scripts" {
		t.Fatal("too long time limit accepted")
	}
	a := admin.get("/audit?q=script.run")
	if !strings.Contains(a.body, "exit code 2") || !strings.Contains(a.body, html.EscapeString("hello <from>")) || !strings.Contains(a.body, "--- script ---") {
		t.Fatal("script and output missing from the audit log")
	}
	for _, want := range []string{"service.stop", "process.kill"} {
		if !strings.Contains(admin.get("/audit?q="+want).body, want) {
			t.Errorf("audit lacks %s", want)
		}
	}
	if !strings.Contains(admin.get("/audit").body, "is intact") {
		t.Fatal("audit chain broken")
	}

	// Power: only known actions (the test does not restart this machine).
	if r := admin.post(base+"/power", "action", "hibernate", "delay", "0"); r.code != http.StatusSeeOther {
		t.Fatalf("power: %d", r.code)
	}
	if r := admin.get(base); !strings.Contains(r.body, "Unknown action.") {
		t.Fatal("unknown power action not refused")
	}

	// A read-only user sees none of it.
	admin.post("/users", "username", "viewer", "password", "viewer password 1", "role", "readonly", "all_customers", "1")
	v := e.client("192.168.1.31")
	v.post("/login", "username", "viewer", "password", "viewer password 1")
	sec := secretRE.FindStringSubmatch(v.get("/login/enroll").body)[1]
	v.post("/login/enroll", "code", e.code(sec))
	v.post("/account/password", "current", "viewer password 1", "password", "viewer password 22", "password2", "viewer password 22")
	for _, path := range []string{"/services", "/processes", "/scripts"} {
		if r := v.get(base + path); r.code != http.StatusForbidden {
			t.Errorf("read-only user opened %s: %d", path, r.code)
		}
	}
	for _, path := range []string{"/scripts", "/power", "/services", "/processes/kill"} {
		if r := v.post(base+path, "action", "restart", "shell", "cmd", "timeout", "30", "script", "ver", "name", "x", "pid", "99"); r.code != http.StatusForbidden {
			t.Errorf("read-only user posted to %s: %d", path, r.code)
		}
	}
}

func windowsDir() string {
	if d := filepath.Clean(os.Getenv("SystemRoot")); d != "." {
		return d
	}
	return `C:\Windows`
}

func TestEventLogs(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows event logs")
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
	base := "/devices/" + itoa(d.ID) + "/events"
	if r := admin.get(base); r.code != http.StatusOK || !strings.Contains(r.body, "Choose a log") {
		t.Fatalf("events page: %d", r.code)
	}
	r := admin.get(base + "?log=System&level=0&hours=720")
	if r.code != http.StatusOK || !strings.Contains(r.body, "events, newest first") {
		t.Fatalf("System log: %d %s", r.code, r.body)
	}
	if r := admin.get(base + "?log=Nope&level=0&hours=24"); !strings.Contains(r.body, "bad event query") {
		t.Fatal("unknown log accepted")
	}
	if !strings.Contains(admin.get("/audit?q=event.query").body, "read the System log") {
		t.Fatal("not audited")
	}
}
