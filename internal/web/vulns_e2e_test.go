package web_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
)

// The scan finds a Windows program's CVEs in NVD (version ranges checked by
// the server) and a Debian package's vulnerabilities in OSV, shows them on
// the pages and opens an alert for critical ones when the policy asks.
func TestVulnScan(t *testing.T) {
	e := newEnv(t)
	var nvdCalls atomic.Int32
	db := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/nvd":
			nvdCalls.Add(1)
			if !strings.HasPrefix(r.URL.Query().Get("virtualMatchString"), "cpe:2.3:a:google:chrome:") {
				_, _ = w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"resultsPerPage":3,"startIndex":0,"totalResults":3,"vulnerabilities":[
				{"cve":{"id":"CVE-2099-0001","descriptions":[{"lang":"en","value":"Heap overflow in Chrome"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8}}]},
					"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*","versionEndExcluding":"121.0"}]}]}]}},
				{"cve":{"id":"CVE-2099-0002","descriptions":[{"lang":"en","value":"Old bug"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5}}]},
					"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*","versionEndExcluding":"100.0"}]}]}]}},
				{"cve":{"id":"CVE-2099-0003","descriptions":[{"lang":"en","value":"Exact version"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":5.0}}]},
					"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:120.0.1:*:*:*:*:*:*:*"}]}]}]}}]}`))
		case r.URL.Path == "/osv/v1/querybatch":
			var q struct {
				Queries []struct {
					Package struct{ Name, Ecosystem string } `json:"package"`
					Version string                           `json:"version"`
				} `json:"queries"`
			}
			_ = json.NewDecoder(r.Body).Decode(&q)
			var res []string
			for _, x := range q.Queries {
				if x.Package.Name == "openssl" && x.Package.Ecosystem == "Debian:12" && x.Version == "3.0.11-1~deb12u2" {
					res = append(res, `{"vulns":[{"id":"DEBIAN-CVE-2099-0100"}]}`)
				} else if x.Package.Name == "bash" {
					res = append(res, `{"vulns":[{"id":"DEBIAN-CVE-2099-0200"}]}`)
				} else {
					res = append(res, `{}`)
				}
			}
			_, _ = w.Write([]byte(`{"results":[` + strings.Join(res, ",") + `]}`))
		case r.URL.Path == "/osv/v1/vulns/DEBIAN-CVE-2099-0200":
			_, _ = w.Write([]byte(`{"id":"DEBIAN-CVE-2099-0200","details":"Bash flaw","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],"affected":[{"package":{"ecosystem":"Debian:12","name":"bash"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`))
		case r.URL.Path == "/osv/v1/vulns/DEBIAN-CVE-2099-0100":
			_, _ = w.Write([]byte(`{"id":"DEBIAN-CVE-2099-0100","details":"OpenSSL flaw","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],"affected":[{"package":{"ecosystem":"Debian:12","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.15-1~deb12u1"}]}]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer db.Close()
	e.srv.NVDURL, e.srv.OSVURL, e.srv.NVDWait = db.URL+"/nvd", db.URL+"/osv", time.Millisecond
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()

	win := e.device(t, "PC-1", "Microsoft Windows 11 Pro")
	deb := e.device(t, "deb-1", "Debian GNU/Linux 12 (bookworm)")
	if err := e.st.SaveInventory(ctx, win.ID, &proto.Inventory{OS: proto.OSInfo{Name: "Microsoft Windows 11 Pro"},
		Software: []proto.Software{{Name: "Google Chrome", Version: "120.0.1"}, {Name: "Unknown Tool", Version: "1.0"}}}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SaveInventory(ctx, deb.ID, &proto.Inventory{OS: proto.OSInfo{Name: "Debian GNU/Linux 12 (bookworm)", Version: "12"},
		Software: []proto.Software{{Name: "libssl3", Version: "3.0.11-1~deb12u2", Source: "openssl", SourceVersion: "3.0.11-1~deb12u2"}, {Name: "bash", Version: "5.2.15-2+b2"}}}); err != nil {
		t.Fatal(err)
	}
	if b := admin.get("/vulnerabilities").body; !strings.Contains(b, `name="enabled"`) {
		t.Fatal("settings form")
	}
	customerPolicy(t, admin, win.CustomerID, "name", "Vulns", "alerts_set", "1", "cpu_percent", "90", "cpu_minutes", "15", "mem_percent", "90",
		"mem_minutes", "15", "disk_percent", "90", "disk_min_free_gb", "5", "offline_minutes", "10080", "reboot_days", "0", "vuln_alerts", "1")
	admin.post("/vulnerabilities/settings", "enabled", "1", "nvd_key", "secret-key")
	waitFor(t, "scan", func() bool {
		return strings.Contains(admin.get("/vulnerabilities?sev=unknown").body, "DEBIAN-CVE-2099-0100")
	})

	b := admin.get("/devices/" + itoa(win.ID) + "/vulnerabilities").body
	if !strings.Contains(b, "CVE-2099-0001") || !strings.Contains(b, "CVE-2099-0003") || strings.Contains(b, "CVE-2099-0002") || !strings.Contains(b, "9.8") {
		t.Fatalf("Windows findings: %s", b)
	}
	if b := admin.get("/devices/" + itoa(deb.ID) + "/vulnerabilities").body; !strings.Contains(b, "openssl") || !strings.Contains(b, "critical") || !strings.Contains(b, "fixed in 3.0.15-1~deb12u1") {
		t.Fatal("Debian findings")
	}
	if b := admin.get("/vulnerabilities?sev=high").body; strings.Contains(b, "DEBIAN-CVE-2099-0200") || !strings.Contains(b, "1 vulnerabilities of Linux packages have no fix") {
		t.Fatal("a vulnerability without a fix is not hidden")
	}
	if b := admin.get("/vulnerabilities?sev=high&fix=all").body; !strings.Contains(b, "DEBIAN-CVE-2099-0200") {
		t.Fatal("fix=all")
	}
	if b := admin.get("/vulnerabilities").body; strings.Contains(b, "secret-key") || !strings.Contains(b, "stored; leave empty to keep it") {
		t.Fatal("the NVD key must not be shown")
	}
	waitFor(t, "alert", func() bool {
		e.srv.CheckAlerts(ctx)
		return strings.Contains(admin.get("/alerts").body, "Critical vulnerability")
	})
	// A second scan within a day uses the cache.
	calls := nvdCalls.Load()
	admin.post("/vulnerabilities/scan")
	time.Sleep(500 * time.Millisecond)
	waitFor(t, "second scan", func() bool { return !strings.Contains(admin.get("/vulnerabilities").body, "scanning now") })
	if nvdCalls.Load() != calls {
		t.Fatal("NVD asked again within a day")
	}
}
