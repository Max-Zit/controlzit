//go:build windows

package web_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/max-zit/controlzit/internal/agent"
	"github.com/max-zit/controlzit/internal/proto"
)

// A policy updates the programs winget knows (not the excluded ones) on its
// day, once; a device that needs a restart after updates gets a request
// with a deadline and is restarted at the deadline; once restarted, the
// request is gone.
func TestProgramUpdatesAndRestart(t *testing.T) {
	e := newEnv(t)
	e.useRealClock()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key

	var mu sync.Mutex
	var upgraded []string
	var restarts []proto.Power
	reboot := true
	oldWinget := agent.SetHandler(proto.KindWinget, func(_ context.Context, raw json.RawMessage) (any, error) {
		var w proto.Winget
		_ = json.Unmarshal(raw, &w)
		mu.Lock()
		defer mu.Unlock()
		switch w.Action {
		case proto.WingetUpgrades:
			return &proto.WingetResult{Packages: []proto.WingetPackage{
				{Name: "Foo Bar", ID: "Foo.Bar", Version: "1.0", Available: "2.0"},
				{Name: "Microsoft 365 Apps", ID: "Microsoft.Office", Version: "16.0", Available: "16.1"},
			}}, nil
		case proto.WingetUpgrade:
			upgraded = append(upgraded, w.ID)
		}
		return &proto.WingetResult{}, nil
	})
	defer func() { agent.SetHandler(proto.KindWinget, oldWinget) }()
	oldPower := agent.SetHandler(proto.KindPower, func(_ context.Context, raw json.RawMessage) (any, error) {
		var p proto.Power
		_ = json.Unmarshal(raw, &p)
		mu.Lock()
		restarts = append(restarts, p)
		mu.Unlock()
		return nil, nil
	})
	defer func() { agent.SetHandler(proto.KindPower, oldPower) }()
	agent.PatchScan = func(context.Context) (*agent.PatchScanResult, error) {
		mu.Lock()
		defer mu.Unlock()
		return &agent.PatchScanResult{RebootRequired: reboot}, nil
	}
	d, stop := startAgent(t, e)
	defer stop()
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()
	now := time.Now()

	pid := customerPolicy(t, admin, d.CustomerID, "name", "Updates",
		"apps_set", "1", "apps_winget", "1", "apps_when", "days", "apps_day", strconv.Itoa(int(now.Weekday())), "apps_hour", strconv.Itoa(now.Hour()),
		"apps_exclude", "Microsoft.Office",
		"updates_set", "1", "mode", "off", "restart_mode", "deadline", "deadline_days", "0")
	if b := admin.get("/policies/" + pid).body; !strings.Contains(b, `name="apps_winget" value="1" checked`) || !strings.Contains(b, `value="deadline" checked`) {
		t.Fatal("policy not saved")
	}

	e.srv.RunAppUpdates(ctx)
	waitFor(t, "program updates", func() bool {
		return strings.Contains(admin.get("/devices/"+itoa(d.ID)+"/activity").body, "1 programs updated, 0 failed, 0 skipped (winget cannot update them), 0 wait for the update ring")
	})
	e.srv.RunAppUpdates(ctx) // once a day
	time.Sleep(500 * time.Millisecond)
	mu.Lock()
	if len(upgraded) != 1 || upgraded[0] != "Foo.Bar" {
		t.Fatalf("upgraded %v", upgraded)
	}
	mu.Unlock()

	// The device needs a restart: request, notice, restart at the deadline.
	base := "/devices/" + itoa(d.ID)
	if r := admin.post(base + "/updates/scan"); r.code != http.StatusSeeOther {
		t.Fatalf("scan: %d", r.code)
	}
	waitFor(t, "restart required", func() bool { return strings.Contains(admin.get(base+"/updates").body, "restart") })
	e.srv.RunRestarts(ctx)
	if b := admin.get(base + "/policy").body; !strings.Contains(b, "A restart is pending") {
		t.Fatal("no restart request on the policy page")
	}
	waitFor(t, "restart at the deadline", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(restarts) == 1 && restarts[0].Action == "restart" && restarts[0].Delay == 600
	})
	e.srv.RunRestarts(ctx) // once per deadline
	time.Sleep(500 * time.Millisecond)
	mu.Lock()
	if len(restarts) != 1 {
		t.Fatalf("restarted %d times", len(restarts))
	}
	reboot = false
	mu.Unlock()
	admin.post(base + "/updates/scan")
	waitFor(t, "scan after the restart", func() bool {
		e.srv.RunRestarts(ctx)
		return !strings.Contains(admin.get(base+"/policy").body, "A restart is pending")
	})
}
