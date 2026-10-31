package web_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/store"
)

// The device list filters by system, alerts and custom fields and starts
// actions on the chosen devices; the search finds devices by serial number
// and address, and programs; the report has the security and health part.
func TestDeviceListSearchReport(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()
	win := e.device(t, "PC-SALES", "Microsoft Windows 11 Pro")
	deb := e.device(t, "deb-web", "Debian GNU/Linux 12 (bookworm)")
	if err := e.st.SaveInventory(ctx, win.ID, &proto.Inventory{OS: proto.OSInfo{Name: "Microsoft Windows 11 Pro"},
		Hardware: proto.Hardware{Serial: "SN-4711"}, Network: []proto.NetAdapter{{Name: "Ethernet", IPs: []string{"10.1.2.3"}}},
		Software: []proto.Software{{Name: "Google Chrome", Version: "120.0"}}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.st.SyncAlerts(ctx, []store.Condition{{DeviceID: win.ID, Kind: "cpu", Severity: "warning", Message: "busy"}}, nil); err != nil {
		t.Fatal(err)
	}
	admin.post("/settings/fields", "action", "add", "scope", "device", "name", "Asset", "kind", "text")
	fid := fieldIDs(admin.get("/settings/fields").body)[0]
	admin.post("/devices/"+itoa(win.ID)+"/fields", "f"+fid, "INV-0042")

	list := func(query string) string { return admin.get("/devices?" + query).body }
	if b := list("os=linux"); !strings.Contains(b, "deb-web") || strings.Contains(b, "PC-SALES") {
		t.Fatal("system filter")
	}
	if b := list("alerts=1"); strings.Contains(b, "deb-web") || !strings.Contains(b, "PC-SALES") {
		t.Fatal("alert filter")
	}
	if b := list("field=" + fid + "&fval=inv-00"); strings.Contains(b, "deb-web") || !strings.Contains(b, "PC-SALES") {
		t.Fatal("field filter")
	}
	if b := list("status=online"); strings.Contains(b, "PC-SALES") || !strings.Contains(b, "No device matches.") {
		t.Fatal("status filter")
	}

	// Restart both (they wait for their agents, as tasks).
	if r := admin.post("/devices/bulk", "ids", itoa(win.ID), "ids", itoa(deb.ID), "action", "restart"); r.code != http.StatusSeeOther {
		t.Fatalf("bulk: %d", r.code)
	}
	for _, id := range []int64{win.ID, deb.ID} {
		if b := admin.get("/devices/" + itoa(id) + "/activity").body; !strings.Contains(b, "Restart in 300 seconds") {
			t.Fatalf("no restart task on %d", id)
		}
	}
	if r := admin.post("/devices/bulk", "ids", itoa(win.ID), "action", "nope"); !strings.Contains(admin.get(r.loc).body, "Unknown action.") {
		t.Fatal("unknown action accepted")
	}

	for q, want := range map[string]string{"sn-4711": "PC-SALES", "10.1.2": "PC-SALES", "chrome": "Google Chrome", "deb": "deb-web"} {
		if b := admin.get("/search?q=" + q).body; !strings.Contains(b, want) {
			t.Fatalf("search %q", q)
		}
	}
	if b := admin.get("/search?q=zzzz").body; !strings.Contains(b, "Nothing found.") {
		t.Fatal("empty search")
	}
	if b := admin.get("/reports/view?customer=" + itoa(win.CustomerID) + "&days=7").body; !strings.Contains(b, "Security and health") {
		t.Fatal("report part")
	}
}
