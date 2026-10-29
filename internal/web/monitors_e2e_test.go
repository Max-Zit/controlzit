package web_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/max-zit/controlzit/internal/agent"
	"github.com/max-zit/controlzit/internal/proto"
)

// Monitors of a policy are sent to the device; too many matching events and
// a stopped process open alerts, and the device page shows the results.
func TestMonitors(t *testing.T) {
	e := newEnv(t)
	e.useRealClock()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	var asked proto.MonitorRun
	old := agent.SetHandler(proto.KindMonitorCheck, func(_ context.Context, raw json.RawMessage) (any, error) {
		_ = json.Unmarshal(raw, &asked)
		return proto.MonitorResults{
			Events:    []proto.EventCount{{Key: "Failed sign-ins", Count: 12}, {Key: "Restarts", Count: 0}},
			Processes: []proto.ProcessState{{Name: "sqlservr.exe", Running: false}, {Name: "explorer", Running: true}},
		}, nil
	})
	defer func() { agent.SetHandler(proto.KindMonitorCheck, old) }()
	d, stop := startAgent(t, e)
	defer stop()
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()

	if r := admin.post("/policies/new", "name", "Bad", "mon_set", "1", "ev_name", "x", "ev_log", "System", "ev_ids", "70000", "ev_source", "",
		"ev_level", "0", "ev_count", "1", "ev_minutes", "15", "ev_severity", "warning"); r.code != http.StatusBadRequest || !strings.Contains(r.body, "not an event ID") {
		t.Fatalf("a bad event ID was accepted: %d", r.code)
	}
	customerPolicy(t, admin, d.CustomerID, "name", "Watch", "mon_set", "1",
		"ev_name", "Failed sign-ins", "ev_log", "Security", "ev_ids", "4625", "ev_source", "", "ev_level", "0", "ev_count", "5", "ev_minutes", "10", "ev_severity", "critical",
		"ev_name", "Restarts", "ev_log", "System", "ev_ids", "41, 6008", "ev_source", "", "ev_level", "0", "ev_count", "1", "ev_minutes", "60", "ev_severity", "warning",
		"proc_name", "sqlservr.exe", "proc_severity", "critical", "proc_name", "explorer", "proc_severity", "warning")

	e.srv.RunMonitorChecks(ctx)
	waitFor(t, "monitor alerts", func() bool { return strings.Contains(admin.get("/alerts").body, "sqlservr.exe is not running") })
	b := admin.get("/alerts").body
	if !strings.Contains(b, "Failed sign-ins: 12 events in the Security log within 10 minutes (IDs 4625)") || strings.Contains(b, "Restarts:") || strings.Contains(b, "explorer is not running") {
		t.Fatal("wrong monitor alerts")
	}
	if len(asked.Events) != 2 || asked.Events[0].Minutes != 10 || len(asked.Events[1].IDs) != 2 || len(asked.Processes) != 2 {
		t.Fatalf("asked %+v", asked)
	}
	if b := admin.get("/devices/" + itoa(d.ID)).body; !strings.Contains(b, "not running") || !strings.Contains(b, "12 events") {
		t.Fatal("device page lacks the monitors")
	}
	if b := admin.get("/devices/" + itoa(d.ID) + "/policy").body; !strings.Contains(b, "Monitors") {
		t.Fatal("device policy lacks the monitors part")
	}
}
