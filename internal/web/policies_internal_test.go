package web

import (
	"testing"

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

// For each part, the device's policy beats the site's, which beats the
// customer's; parts a policy does not set come from the next level or the
// server.
func TestPolicyResolution(t *testing.T) {
	cust := &policyLevel{Level: "customer", Policy: &store.Policy{ID: 1, Name: "Customer"}, Settings: PolicySettings{
		Updates:  &PatchPolicy{Mode: PatchAutoAll, Days: []int{1}, Hour: 2},
		Software: &SoftwarePolicy{Required: []RequiredApp{{Source: "winget", ID: "7zip.7zip", Match: "7-Zip"}}},
	}}
	site := &policyLevel{Level: "site", Policy: &store.Policy{ID: 2, Name: "Site"}, Settings: PolicySettings{
		Updates: &PatchPolicy{Mode: PatchAutoSecurity, Days: []int{3}, Hour: 4},
		Alerts:  &AlertRules{CPUPercent: 70, CPUMinutes: 5, MemPercent: 80, MemMinutes: 5, DiskPercent: 85, OfflineMinutes: 30},
	}}
	dev := &policyLevel{Level: "device", Policy: &store.Policy{ID: 3, Name: "Device"}, Settings: PolicySettings{
		Automations: &AutomationPolicy{Runs: []Automation{{ScriptID: 9, Days: []int{5}, Minute: 60}}},
	}}
	pr := &policyResolver{
		byTarget: map[string]*policyLevel{"customer:10": cust, "site:20": site, "device:30": dev},
		scopes: map[int64]store.DeviceScope{
			30: {DeviceID: 30, SiteID: 20, CustomerID: 10}, // all three levels
			31: {DeviceID: 31, SiteID: 21, CustomerID: 10}, // customer only
			32: {DeviceID: 32, SiteID: 22, CustomerID: 11}, // nothing
		},
	}
	def := defaultPatchPolicy()
	if u, l := pr.updates(30, def); l != site || u.Mode != PatchAutoSecurity {
		t.Fatalf("device 30 updates from %v", l)
	}
	if u, l := pr.updates(31, def); l != cust || u.Mode != PatchAutoAll {
		t.Fatal("device 31 updates")
	}
	if u, l := pr.updates(32, def); l != nil || u.Mode != def.Mode {
		t.Fatal("device 32 updates")
	}
	if sw, l := pr.software(30); l != cust || len(sw.Required) != 1 {
		t.Fatal("software is inherited from the customer")
	}
	m := defaultMonitoring()
	m.Recipients = []string{"it@example.com"}
	if a, l := pr.alerts(30, m); l != site || a.CPUPercent != 70 || len(a.Recipients) != 1 {
		t.Fatal("alert thresholds from the site, emails from the server")
	}
	if a, l := pr.alerts(31, m); l != nil || a.CPUPercent != m.CPUPercent {
		t.Fatal("device 31 alerts")
	}
	if au, l := pr.automations(30); l != dev || au.Runs[0].ScriptID != 9 {
		t.Fatal("automations of the device")
	}
	if len(pr.chain(30)) != 3 || len(pr.chain(32)) != 0 || pr.chain(99) != nil {
		t.Fatal("chains")
	}
}

func TestPolicyValidate(t *testing.T) {
	ok := PolicySettings{Software: &SoftwarePolicy{Required: []RequiredApp{{Source: "library", ID: "4", Match: "Test"}}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]PolicySettings{
		"bad source":     {Software: &SoftwarePolicy{Required: []RequiredApp{{Source: "ftp", ID: "x", Match: "xx"}}}},
		"short match":    {Software: &SoftwarePolicy{Required: []RequiredApp{{Source: "winget", ID: "a.b", Match: "x"}}}},
		"bad mode":       {Updates: &PatchPolicy{Mode: "sometimes"}},
		"cpu too low":    {Alerts: &AlertRules{CPUPercent: 10, CPUMinutes: 5, MemPercent: 90, MemMinutes: 5, DiskPercent: 90, OfflineMinutes: 15}},
		"automation day": {Automations: &AutomationPolicy{Runs: []Automation{{ScriptID: 1, Minute: 10}}}},
	} {
		if p.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAppInstalled(t *testing.T) {
	inv := &proto.Inventory{Software: []proto.Software{{Name: "7-Zip 25.01 (x64)"}, {Name: "Google Chrome"}}}
	if !appInstalled(inv, "7-zip") || !appInstalled(inv, " chrome ") || appInstalled(inv, "Firefox") || appInstalled(nil, "x") {
		t.Fatal("appInstalled")
	}
}
