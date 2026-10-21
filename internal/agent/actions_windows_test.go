//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/max-zit/controlzit/internal/proto"
)

func TestListServicesAndProcesses(t *testing.T) {
	svcs, err := listServices()
	if err != nil || len(svcs) < 20 {
		t.Fatalf("services: %d %v", len(svcs), err)
	}
	found := false
	for _, s := range svcs {
		if strings.EqualFold(s.Name, "EventLog") && s.State == "running" {
			found = true
		}
	}
	if !found {
		t.Error("EventLog service not listed as running")
	}
	ps, err := listProcesses()
	if err != nil || len(ps) < 10 {
		t.Fatalf("processes: %d %v", len(ps), err)
	}
}

func TestRunScript(t *testing.T) {
	helperDir = t.TempDir()
	run := func(a proto.ScriptRun) proto.ScriptResult {
		t.Helper()
		raw, _ := json.Marshal(a)
		out, err := runScript(context.Background(), raw)
		if err != nil {
			t.Fatal(err)
		}
		return out.(proto.ScriptResult)
	}
	r := run(proto.ScriptRun{Shell: "powershell", Script: "Write-Output 'hello from ps čćšđž'\nWrite-Error 'bad thing'\nexit 3", Timeout: 60})
	if r.ExitCode != 3 || !strings.Contains(r.Output, "hello from ps čćšđž") || !strings.Contains(r.Output, "bad thing") || strings.Contains(r.Output, "CLIXML") {
		t.Fatalf("powershell: %+v", r)
	}
	r = run(proto.ScriptRun{Shell: "powershell", Script: "Get-Date | Out-Null", Timeout: 60})
	if r.ExitCode != 0 {
		t.Fatalf("powershell without exit: %+v", r)
	}
	r = run(proto.ScriptRun{Shell: "cmd", Script: "echo šđž\nexit /b 4", Timeout: 30})
	if r.ExitCode != 4 || !strings.Contains(r.Output, "šđž") {
		t.Fatalf("cmd exit code: %+v", r)
	}
	r = run(proto.ScriptRun{Shell: "cmd", Script: "echo hello from cmd\nver", Timeout: 30})
	if r.ExitCode != 0 || !strings.Contains(r.Output, "hello from cmd") || !strings.Contains(r.Output, "Windows") {
		t.Fatalf("cmd: %+v", r)
	}
	r = run(proto.ScriptRun{Shell: "powershell", Script: "Start-Sleep 30", Timeout: 5})
	if !r.TimedOut {
		t.Fatalf("timeout: %+v", r)
	}
	if _, err := runScript(context.Background(), json.RawMessage(`{"shell":"bash","script":"x","timeout":10}`)); err == nil {
		t.Fatal("unknown shell accepted")
	}
}

func TestKillRefusesCritical(t *testing.T) {
	for _, a := range []proto.ProcKill{{PID: 4, Name: "System"}, {PID: 1234, Name: "lsass.exe"}, {PID: 999999, Name: "nothere.exe"}} {
		raw, _ := json.Marshal(a)
		if _, err := killProcess(context.Background(), raw); err == nil {
			t.Errorf("kill %+v accepted", a)
		}
	}
}
