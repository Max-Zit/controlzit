package web

import (
	"encoding/json"
	"testing"

	"github.com/max-zit/controlzit/internal/proto"
)

func TestCmpVersion(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"120.0.6099.109", "120.0.6099.110", -1},
		{"7.01", "7.01.0", 0},
		{"24.08", "24.8", 0},
		{"2.10", "2.9", 1},
		{"1.0", "1.0-beta", 1},
		{"1.0-beta", "1.0-rc", -1},
	} {
		if got := cmpVersion(c.a, c.b); got != c.want {
			t.Errorf("cmp(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	r := verRange{SI: "100", EE: "120.0.6099.129"}
	if !r.matches("120.0.6099.109") || r.matches("120.0.6099.129") || r.matches("99.9") || !(verRange{V: "1.2"}).matches("1.2.0") {
		t.Fatal("ranges")
	}
}

// CVSS v3.1 base scores of well-known vectors.
func TestCVSS3(t *testing.T) {
	for v, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H": 9.6,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N":            0,
	} {
		if got := cvss3Score(v); got != want {
			t.Errorf("%s: %v, want %v", v, got, want)
		}
	}
	if severityOf(9.8) != "critical" || severityOf(7) != "high" || severityOf(0) != "unknown" {
		t.Fatal("severity")
	}
}

func TestCatalogAndEcosystem(t *testing.T) {
	if a, v := catalogApp("Google Chrome", "141.0.1"); a == nil || a.product != "chrome" || v != "141.0.1" {
		t.Fatal("chrome")
	}
	if a, v := catalogApp("Python 3.12.4 (64-bit)", "3.12.4150.0"); a == nil || v != "3.12.4" {
		t.Fatalf("python version %q", v)
	}
	if a, _ := catalogApp("Mozilla Firefox ESR (x64 en-US)", "128.3"); a == nil || a.product != "firefox_esr" {
		t.Fatal("firefox esr")
	}
	if a, _ := catalogApp("Adobe Acrobat (64-bit)", "24.1"); a == nil || a.product != "acrobat_dc" {
		t.Fatal("acrobat")
	}
	if a, v := catalogApp("Microsoft .NET Runtime - 8.0.1 (x64)", "64.4.33213"); a == nil || a.product != ".net" || v != "8.0.1" {
		t.Fatalf(".NET %q", v)
	}
	if a, v := catalogApp("Visual Studio Community 2022", "17.8.34511.84"); a == nil || v != "17.8.34511.84" {
		t.Fatalf("Visual Studio %q", v)
	}
	if a, _ := catalogApp("Some Tool", "1"); a != nil {
		t.Fatal("unknown program matched")
	}
	for os, want := range map[proto.OSInfo]string{
		{Name: "Ubuntu 22.04.4 LTS", Version: "22.04"}:            "Ubuntu:22.04:LTS",
		{Name: "Ubuntu 23.10", Version: "23.10"}:                  "Ubuntu:23.10",
		{Name: "Debian GNU/Linux 12 (bookworm)", Version: "12"}:   "Debian:12",
		{Name: "Rocky Linux 9", Version: "9.4"}:                   "",
		{Name: "Microsoft Windows 11 Pro", Version: "10.0.26100"}: "",
	} {
		if got := osvEcosystem(os); got != want {
			t.Errorf("%s: %q", os.Name, got)
		}
	}
}

// entryOf keeps the product's version ranges and its score.
func TestEntryOf(t *testing.T) {
	var c nvdCVE
	_ = json.Unmarshal([]byte(`{"id":"CVE-2024-1","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"Use after free"}],
		"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8.8,"baseSeverity":"HIGH"}}]},
		"configurations":[{"nodes":[{"cpeMatch":[
			{"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*","versionEndExcluding":"120.0.6099.129"},
			{"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"},
			{"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:118.0.1:*:*:*:*:*:*:*"},
			{"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"},
			{"vulnerable":true,"criteria":"cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*"}]}]}]}`), &c)
	e, ok := entryOf(c, "google", "chrome")
	if !ok || e.Score != 8.8 || len(e.Ranges) != 2 || e.Ranges[0].EE != "120.0.6099.129" || e.Ranges[1].V != "118.0.1" || e.Summary != "Use after free" {
		t.Fatalf("%+v", e)
	}
	c.Status = "Rejected"
	if _, ok := entryOf(c, "google", "chrome"); ok {
		t.Fatal("rejected CVE kept")
	}
}
