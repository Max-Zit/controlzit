package web

import (
	"net/http"
	"sort"
	"strings"

	"github.com/max-zit/controlzit/internal/store"
)

// severityRank orders severities (for filters and sorting).
var severityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}

// vulnRow is a program version and its vulnerabilities on the devices.
type vulnRow struct {
	Product, Version, Source string
	Counts                   map[string]int
	Worst                    string
	Score                    float64
	IDs                      []string // the worst few
	Devices                  []vulnDev
	Shown                    []vulnDev // the first devices
	More                     int
	Badges                   []sevCount
}

type sevCount struct {
	Severity string
	N        int
}

// severities in order, worst first.
var severities = []string{"critical", "high", "medium", "low", "unknown"}

type vulnDev struct {
	ID       int64
	Hostname string
}

type vulnsData struct {
	Settings VulnSettings
	HasKey   bool
	Scanning bool
	Min      string
	All      bool // also vulnerabilities without a fix
	Unfixed  int  // hidden because there is no fix yet
	Levels   []string
	Rows     []vulnRow
	Totals   map[string]int
	Devices  int
}

func (s *Server) handleVulns(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	ctx := r.Context()
	d := &vulnsData{Settings: s.vulnSettings(ctx), Scanning: s.vulns.running(), Min: r.FormValue("sev"), Totals: map[string]int{}, Levels: severities, All: r.FormValue("fix") == "all"}
	d.HasKey, d.Settings.NVDKey = d.Settings.NVDKey != "", ""
	if _, ok := severityRank[d.Min]; !ok {
		d.Min = "high"
	}
	list, err := s.store.DeviceVulns(ctx, 0)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	rows := map[string]*vulnRow{}
	devs := map[int64]bool{}
	for _, v := range list {
		if !u.SeesCustomer(v.CustomerID) {
			continue
		}
		shown := severityRank[v.Severity] >= severityRank[d.Min]
		if v.Fix == "none" && !d.All {
			if shown {
				d.Unfixed++
			}
			continue
		}
		d.Totals[v.Severity]++
		if !shown {
			continue
		}
		devs[v.DeviceID] = true
		k := v.Product + "\x00" + v.Version
		row := rows[k]
		if row == nil {
			row = &vulnRow{Product: v.Product, Version: v.Version, Source: v.Source, Counts: map[string]int{}, Worst: v.Severity}
			rows[k] = row
		}
		if !containsStr(row.IDs, v.ID) {
			row.Counts[v.Severity]++
			if len(row.IDs) < 3 {
				row.IDs = append(row.IDs, v.ID)
			}
		}
		if v.Score > row.Score {
			row.Score = v.Score
		}
		if severityRank[v.Severity] > severityRank[row.Worst] {
			row.Worst = v.Severity
		}
		seen := false
		for _, x := range row.Devices {
			seen = seen || x.ID == v.DeviceID
		}
		if !seen {
			row.Devices = append(row.Devices, vulnDev{ID: v.DeviceID, Hostname: v.Hostname})
		}
	}
	for _, row := range rows {
		for _, sv := range severities {
			if n := row.Counts[sv]; n > 0 {
				row.Badges = append(row.Badges, sevCount{sv, n})
			}
		}
		row.Shown = row.Devices[:min(5, len(row.Devices))]
		row.More = len(row.Devices) - len(row.Shown)
		d.Rows = append(d.Rows, *row)
	}
	sort.Slice(d.Rows, func(i, j int) bool {
		a, b := d.Rows[i], d.Rows[j]
		if severityRank[a.Worst] != severityRank[b.Worst] {
			return severityRank[a.Worst] > severityRank[b.Worst]
		}
		if len(a.Devices) != len(b.Devices) {
			return len(a.Devices) > len(b.Devices)
		}
		return strings.ToLower(a.Product) < strings.ToLower(b.Product)
	})
	d.Devices = len(devs)
	s.render(w, r, http.StatusOK, "vulns", &Page{Title: "Vulnerabilities", Nav: "vulns", Data: d})
}

func containsStr(list []string, x string) bool {
	for _, y := range list {
		if y == x {
			return true
		}
	}
	return false
}

func (s *Server) handleVulnSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v := s.vulnSettings(ctx)
	v.Enabled = r.FormValue("enabled") == "1"
	if k := strings.TrimSpace(r.FormValue("nvd_key")); k != "" {
		v.NVDKey = s.store.SealSecret("settings.vulns.nvd_key", k)
	}
	if r.FormValue("clear_key") == "1" {
		v.NVDKey = ""
	}
	if err := s.store.SetSetting(ctx, settingVulns, v); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.vulns", "settings", "vulnerability scan on: %v, NVD API key set: %v", v.Enabled, v.NVDKey != "")
	if v.Enabled && v.LastScan.IsZero() {
		s.startVulnScan()
	}
	s.redirect(w, r, "/vulnerabilities", "Saved.")
}

func (s *Server) handleVulnScan(w http.ResponseWriter, r *http.Request) {
	if !s.vulnSettings(r.Context()).Enabled {
		s.redirect(w, r, "/vulnerabilities", "Switch the vulnerability scan on first.")
		return
	}
	if !s.startVulnScan() {
		s.redirect(w, r, "/vulnerabilities", "A scan is already running.")
		return
	}
	s.audit(r, "vulns.scan", "settings", "vulnerability scan started")
	s.redirect(w, r, "/vulnerabilities", "The scan runs in the background; the first one can take several minutes.")
}

type deviceVulnsData struct {
	D       *store.Device
	List    []store.DeviceVuln
	Enabled bool
}

func (s *Server) handleDeviceVulns(w http.ResponseWriter, r *http.Request) {
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	list, err := s.store.DeviceVulns(r.Context(), d.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "devicevulns", &Page{Title: d.Hostname, Nav: "devices",
		Data: &deviceVulnsData{D: d, List: list, Enabled: s.vulnSettings(r.Context()).Enabled}})
}
