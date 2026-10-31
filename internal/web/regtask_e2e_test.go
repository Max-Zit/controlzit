package web_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/max-zit/rmmzit/internal/agent"
	"github.com/max-zit/rmmzit/internal/proto"
)

// The registry and task pages send the right commands, show the answers and
// audit the changes (with the value a registry change replaced).
func TestRegistryAndTasksPages(t *testing.T) {
	e := newEnv(t)
	e.useRealClock()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	var mu sync.Mutex
	var got []string
	record := func(s string) { mu.Lock(); got = append(got, s); mu.Unlock() }
	restore := []func(){}
	set := func(kind string, fn func(context.Context, json.RawMessage) (any, error)) {
		old := agent.SetHandler(kind, fn)
		restore = append(restore, func() { agent.SetHandler(kind, old) })
	}
	defer func() {
		for _, f := range restore {
			f()
		}
	}()
	set(proto.KindRegList, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a proto.RegPath
		_ = json.Unmarshal(raw, &a)
		return proto.RegKey{Path: a.Path, Subkeys: []string{"Vendor App"}, Values: []proto.RegValue{{Name: "Level", Type: "REG_DWORD", Data: "3"}, {Name: "Blob", Type: "REG_BINARY", Data: "00ff"}}}, nil
	})
	set(proto.KindRegSet, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a proto.RegSet
		_ = json.Unmarshal(raw, &a)
		record("set " + a.Path + " " + a.Name + "=" + a.Data)
		return map[string]any{"old": proto.RegValue{Name: "Level", Type: "REG_DWORD", Data: "3"}}, nil
	})
	set(proto.KindRegDelete, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a proto.RegDelete
		_ = json.Unmarshal(raw, &a)
		if a.Key && proto.ProtectedRegKey(a.Path) {
			return nil, errors.New("this key is protected and cannot be deleted from the console")
		}
		record("delete " + a.Path)
		return nil, nil
	})
	set(proto.KindTaskList, func(context.Context, json.RawMessage) (any, error) {
		return []proto.SchedTask{{Path: `\`, Name: "Nightly cleanup", State: "Ready", LastRun: "2026-10-28T02:00:00Z", LastResult: 0x41303, Action: "cleanmgr.exe /sagerun:1"}}, nil
	})
	set(proto.KindTaskCtl, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a proto.TaskControl
		_ = json.Unmarshal(raw, &a)
		record("task " + a.Action + " " + a.Name)
		return nil, nil
	})
	d, stop := startAgent(t, e)
	defer stop()
	admin, _ := e.setupAdmin("192.168.1.10")
	base := "/devices/" + itoa(d.ID)

	if b := admin.get(base + "/registry?path=HKEY_LOCAL_MACHINE/SOFTWARE/MaxZit").body; !strings.Contains(b, "Vendor App") || !strings.Contains(b, `HKLM\SOFTWARE\MaxZit`) || !strings.Contains(b, "00ff") {
		t.Fatal("registry page")
	}
	if b := admin.get(base + "/registry?path=HKCU").body; !strings.Contains(b, "unknown registry root") {
		t.Fatal("HKCU not refused")
	}
	admin.post(base+"/registry", "path", `HKLM\SOFTWARE\MaxZit`, "action", "set", "name", "Level", "type", "REG_DWORD", "data", "5")
	admin.post(base+"/registry", "path", `HKLM\SOFTWARE\MaxZit\Old`, "action", "deletekey")
	r := admin.post(base+"/registry", "path", `HKLM\SOFTWARE`, "action", "deletekey")
	if b := admin.get(r.loc).body; !strings.Contains(b, "protected") {
		t.Fatal("protected key error not shown")
	}
	if b := admin.get(base + "/tasks").body; !strings.Contains(b, "Nightly cleanup") || !strings.Contains(b, "not run yet") {
		t.Fatal("tasks page")
	}
	admin.post(base+"/tasks", "path", `\`, "name", "Nightly cleanup", "action", "disable")
	if r := admin.post(base+"/tasks", "path", `\`, "name", "x'; rm", "action", "run"); !strings.Contains(admin.get(r.loc).body, "Unknown action") {
		t.Fatal("bad task name not refused")
	}
	mu.Lock()
	want := []string{`set HKLM\SOFTWARE\MaxZit Level=5`, `delete HKLM\SOFTWARE\MaxZit\Old`, "task disable Nightly cleanup"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("commands %q", got)
	}
	mu.Unlock()
	if b := admin.get("/audit?q=registry").body; !strings.Contains(b, "REG_DWORD 3 → REG_DWORD 5") {
		t.Fatal("registry change not audited with the old value")
	}
	if b := admin.get("/audit?q=schedtask").body; !strings.Contains(b, "disable of the scheduled task") {
		t.Fatal("task change not audited")
	}
}
