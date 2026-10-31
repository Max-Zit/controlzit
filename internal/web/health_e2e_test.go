package web_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/max-zit/rmmzit/internal/agent"
	"github.com/max-zit/rmmzit/internal/proto"
)

// Network checks of a policy run on the device and open alerts when they
// fail longer than their minutes or a certificate expires soon; disk and
// RAID problems the device reports open alerts too.
func TestNetChecksAndDiskHealth(t *testing.T) {
	e := newEnv(t)
	e.useRealClock()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	oldNet := agent.SetHandler(proto.KindNetCheck, func(_ context.Context, raw json.RawMessage) (any, error) {
		var in proto.NetCheckRun
		_ = json.Unmarshal(raw, &in)
		var out proto.NetCheckResults
		for _, c := range in.Checks {
			r := proto.NetCheckResult{Name: c.Name, OK: true, MS: 3}
			switch c.Name {
			case "Shop":
				r = proto.NetCheckResult{Name: c.Name, Error: "HTTP 503"}
			case "Portal":
				r.CertDays = 5
			}
			out.Results = append(out.Results, r)
		}
		return out, nil
	})
	defer func() { agent.SetHandler(proto.KindNetCheck, oldNet) }()
	oldDisk := agent.SetHandler(proto.KindDiskHealth, func(context.Context, json.RawMessage) (any, error) {
		return proto.DiskHealth{
			Disks:  []proto.PhysicalDisk{{Model: "Old Disk 500", Serial: "S1", Media: "HDD", Health: proto.HealthWarning, Errors: 8, Wear: -1}, {Model: "Good SSD", Health: proto.HealthOK, Wear: 3}},
			Arrays: []proto.RAIDArray{{Name: "md0", Level: "raid1", Health: proto.HealthWarning, State: "degraded [2/1] [U_]"}},
		}, nil
	})
	defer func() { agent.SetHandler(proto.KindDiskHealth, oldDisk) }()
	d, stop := startAgent(t, e)
	defer stop()
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()

	if r := admin.post("/policies/new", "name", "Bad", "net_set", "1", "net_name", "x", "net_kind", "tcp", "net_target", "host", "net_port", "", "net_minutes", "3"); r.code != http.StatusBadRequest || !strings.Contains(r.body, "a TCP check needs a port") {
		t.Fatal("a TCP check without a port was accepted")
	}
	customerPolicy(t, admin, d.CustomerID, "name", "Checks", "net_set", "1",
		"net_name", "Router", "net_kind", "ping", "net_target", "192.168.1.1", "net_port", "", "net_minutes", "1",
		"net_name", "Shop", "net_kind", "http", "net_target", "https://shop.example/", "net_port", "", "net_minutes", "1",
		"net_name", "Portal", "net_kind", "http", "net_target", "https://portal.example/", "net_port", "", "net_minutes", "1",
		"alerts_set", "1", "cpu_percent", "90", "cpu_minutes", "15", "mem_percent", "90", "mem_minutes", "15", "disk_percent", "100",
		"disk_min_free_gb", "0", "offline_minutes", "15", "reboot_days", "0", "disk_health", "1")

	base := "/devices/" + itoa(d.ID)
	e.srv.RunNetChecks(ctx)
	waitFor(t, "network check results", func() bool { return strings.Contains(admin.get(base).body, "HTTP 503") })
	e.srv.RunDiskHealth(ctx)
	waitFor(t, "disk health", func() bool { return strings.Contains(admin.get(base).body, "Old Disk 500") })

	// The failing check is new: no alert yet; after its minute, an alert.
	e.srv.CheckAlerts(ctx)
	if b := admin.get("/alerts").body; strings.Contains(b, "Network check failed") || !strings.Contains(b, "Certificate expires soon") ||
		!strings.Contains(b, "Disk health problem") || !strings.Contains(b, "RAID array degraded") {
		t.Fatalf("alerts before the minute: %s", b)
	}
	if _, err := e.st.Pool().Exec(ctx, `UPDATE net_check_state SET failing_since = failing_since - interval '5 minutes' WHERE name='Shop'`); err != nil {
		t.Fatal(err)
	}
	e.srv.CheckAlerts(ctx)
	if b := admin.get("/alerts").body; !strings.Contains(b, "Network check failed") || !strings.Contains(b, "shop.example") {
		t.Fatal("no alert for the failing check")
	}
}
