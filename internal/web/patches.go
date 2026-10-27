package web

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

// Windows Update: the agents report missing updates (patch reports); the
// console shows them per device and for all devices, installs chosen
// updates, and installs automatically on a schedule (patch policy).

const settingPatchPolicy = "patch_policy"

// Patch policy modes.
const (
	PatchAutoOff      = "off"
	PatchAutoSecurity = "security"
	PatchAutoAll      = "all"
)

// PatchPolicy is the schedule of automatic installations.
type PatchPolicy struct {
	Mode   string `json:"mode"`   // off, security, all (feature upgrades never)
	Days   []int  `json:"days"`   // time.Weekday values
	Hour   int    `json:"hour"`   // server time, 0–23
	Reboot bool   `json:"reboot"` // restart when an installation needs it
}

func defaultPatchPolicy() PatchPolicy {
	return PatchPolicy{Mode: PatchAutoOff, Days: []int{3}, Hour: 3}
}

// Patches loads the patch policy.
func (s *Server) Patches(ctx context.Context) PatchPolicy {
	p := defaultPatchPolicy()
	if err := s.store.GetSetting(ctx, settingPatchPolicy, &p); err != nil {
		return defaultPatchPolicy()
	}
	return p
}

// Day reports whether the policy runs on weekday d.
func (p PatchPolicy) Day(d int) bool {
	for _, x := range p.Days {
		if x == d {
			return true
		}
	}
	return false
}

// pick selects the updates the policy installs.
func (p PatchPolicy) pick(r *proto.PatchReport) []string {
	var ids []string
	for i := range r.Updates {
		u := &r.Updates[i]
		if u.Upgrade() || (p.Mode == PatchAutoSecurity && !u.Security()) {
			continue
		}
		ids = append(ids, u.ID)
	}
	if len(ids) > proto.MaxPatchInstall {
		ids = ids[:proto.MaxPatchInstall]
	}
	return ids
}

// savePatchReport stores a report from an agent (agent channel).
func (s *Server) savePatchReport(ctx context.Context, d *store.Device, r *proto.PatchReport) error {
	if len(r.Updates) > 1000 {
		r.Updates = r.Updates[:1000]
	}
	if len(r.History) > 50 {
		r.History = r.History[:50]
	}
	if r.Install != nil && len(r.Install.Results) > proto.MaxPatchInstall {
		r.Install.Results = r.Install.Results[:proto.MaxPatchInstall]
	}
	prev, err := s.store.SavePatchReport(ctx, d.ID, r)
	if err != nil {
		return err
	}
	// Write the outcome of a finished installation to the audit log once.
	if in := r.Install; in != nil && !in.Finished.IsZero() && (prev == nil || prev.Install == nil || !prev.Install.Finished.Equal(in.Finished)) {
		ok, failed := 0, 0
		for _, x := range in.Results {
			if x.Result == 2 || x.Result == 3 {
				ok++
			} else {
				failed++
			}
		}
		detail := "updates on " + d.Hostname + ": " + strconv.Itoa(ok) + " installed, " + strconv.Itoa(failed) + " failed"
		if in.Error != "" {
			detail += "; error: " + in.Error
		}
		if in.RebootRequired {
			detail += "; restart required"
			if in.Rebooting {
				detail += " (restarting in 5 minutes)"
			}
		}
		_ = s.store.Audit(ctx, "agent", "", "patch.result", "device:"+strconv.FormatInt(d.ID, 10), detail)
	}
	return nil
}

// ---- device page

type devicePatchesData struct {
	D        *store.Device
	Online   bool
	Report   *proto.PatchReport
	At       time.Time
	Security int
}

func (s *Server) handleDevicePatches(w http.ResponseWriter, r *http.Request) {
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	rep, at, err := s.store.PatchReport(r.Context(), d.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	pd := &devicePatchesData{D: d, Online: s.Connected(d.ID), Report: rep, At: at}
	if rep != nil {
		sort.SliceStable(rep.Updates, func(i, j int) bool { return rep.Updates[i].Security() && !rep.Updates[j].Security() })
		for i := range rep.Updates {
			if rep.Updates[i].Security() {
				pd.Security++
			}
		}
	}
	s.render(w, r, http.StatusOK, "patches", &Page{Title: d.Hostname, Nav: "devices", Data: pd})
}

func (s *Server) handlePatchScan(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	s.startTask(w, r, d, "patch.scan", "Search for updates", nil, struct{}{})
}

func (s *Server) handlePatchInstall(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	back := s.deviceURL(d, "/updates")
	if err := r.ParseForm(); err != nil {
		s.redirect(w, r, back, "Choose at least one update.")
		return
	}
	rep, _, err := s.store.PatchReport(r.Context(), d.ID)
	if err != nil || rep == nil {
		s.redirect(w, r, back, "Choose at least one update.")
		return
	}
	known := map[string]string{}
	for _, u := range rep.Updates {
		known[strings.ToLower(u.ID)] = u.Title
	}
	var ids, titles []string
	for _, id := range r.Form["id"] {
		if t, ok := known[strings.ToLower(id)]; ok && proto.ValidUpdateID(id) && len(ids) < proto.MaxPatchInstall {
			ids, titles = append(ids, id), append(titles, t)
		}
	}
	if len(ids) == 0 {
		s.redirect(w, r, back, "Choose at least one update.")
		return
	}
	in := proto.PatchInstall{IDs: ids, Reboot: r.FormValue("reboot") == "1", By: s.issuer(r)}
	s.startTask(w, r, d, "patch.install", "Install %s updates", []string{strconv.Itoa(len(ids))}, patchInstallTask{PatchInstall: in, Titles: titles})
}

// ---- all devices

type patchRow struct {
	store.DevicePatches
	Online   bool
	Missing  int
	Security int
}

type patchOverviewData struct {
	Rows     []patchRow
	Policy   PatchPolicy
	Missing  int // devices with missing updates
	Reboot   int
	NoReport int
	Filter   string
}

func (s *Server) handlePatchOverview(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.PatchOverview(r.Context(), userFrom(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	pd := &patchOverviewData{Policy: s.Patches(r.Context()), Filter: r.FormValue("show")}
	for _, dp := range list {
		row := patchRow{DevicePatches: dp, Online: s.Connected(dp.ID)}
		if rep := dp.Report; rep != nil {
			row.Missing = len(rep.Updates)
			for i := range rep.Updates {
				if rep.Updates[i].Security() {
					row.Security++
				}
			}
			if row.Missing > 0 {
				pd.Missing++
			}
			if rep.RebootRequired {
				pd.Reboot++
			}
		} else {
			pd.NoReport++
		}
		switch pd.Filter {
		case "missing":
			if row.Missing == 0 {
				continue
			}
		case "security":
			if row.Security == 0 {
				continue
			}
		case "reboot":
			if dp.Report == nil || !dp.Report.RebootRequired {
				continue
			}
		}
		pd.Rows = append(pd.Rows, row)
	}
	s.render(w, r, http.StatusOK, "patchoverview", &Page{Title: "Updates", Nav: "updates", Data: pd})
}

// ---- policy

var weekdays = []int{1, 2, 3, 4, 5, 6, 0}

type patchPolicyData struct {
	P     PatchPolicy
	Days  []int
	Hours []int
}

func (s *Server) handlePatchPolicy(w http.ResponseWriter, r *http.Request) {
	hours := make([]int, 24)
	for i := range hours {
		hours[i] = i
	}
	s.render(w, r, http.StatusOK, "patchpolicy", &Page{Title: "Windows updates", Nav: "settings", Data: &patchPolicyData{P: s.Patches(r.Context()), Days: weekdays, Hours: hours}})
}

func (s *Server) handlePatchPolicySave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.redirect(w, r, "/settings/updates", "Unknown action.")
		return
	}
	p := PatchPolicy{Mode: r.FormValue("mode"), Reboot: r.FormValue("reboot") == "1"}
	p.Hour, _ = strconv.Atoi(r.FormValue("hour"))
	for _, v := range r.Form["day"] {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 6 && !p.Day(n) {
			p.Days = append(p.Days, n)
		}
	}
	if (p.Mode != PatchAutoOff && p.Mode != PatchAutoSecurity && p.Mode != PatchAutoAll) || p.Hour < 0 || p.Hour > 23 {
		s.redirect(w, r, "/settings/updates", "Unknown action.")
		return
	}
	if p.Mode != PatchAutoOff && len(p.Days) == 0 {
		s.redirect(w, r, "/settings/updates", "Choose at least one day.")
		return
	}
	sort.Ints(p.Days)
	if err := s.store.SetSetting(r.Context(), settingPatchPolicy, p); err != nil {
		s.serverError(w, r, err)
		return
	}
	raw, _ := json.Marshal(p)
	s.audit(r, "settings.patches", "settings", "Windows update policy: %s", raw)
	s.redirect(w, r, "/settings/updates", "Saved.")
}

// RunPatchSchedule starts the automatic installations that are due (called
// every minute by the monitor loop).
func (s *Server) RunPatchSchedule(ctx context.Context) {
	def := s.Patches(ctx)
	pr, err := s.loadPolicies(ctx)
	if err != nil {
		s.log.Warn("patch schedule: cannot load policies", "err", err)
		return
	}
	now := s.now().Local()
	list, err := s.store.PatchOverview(ctx, nil)
	if err != nil {
		s.log.Warn("patch schedule: cannot load devices", "err", err)
		return
	}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	for _, dp := range list {
		// The device's policy, or the server's settings.
		p, _ := pr.updates(dp.ID, def)
		if p.Mode == PatchAutoOff || !p.Day(int(now.Weekday())) || now.Hour() != p.Hour {
			continue
		}
		rep := dp.Report
		if rep == nil || rep.State != proto.PatchIdle || !s.Connected(dp.ID) ||
			(dp.AutoInstallOn != nil && dp.AutoInstallOn.Format("2006-01-02") == today.Format("2006-01-02")) {
			continue
		}
		ids := p.pick(rep)
		if err := s.store.MarkAutoInstall(ctx, dp.ID, today); err != nil {
			s.log.Warn("patch schedule", "device", dp.ID, "err", err)
			continue
		}
		if len(ids) == 0 {
			continue
		}
		in := proto.PatchInstall{IDs: ids, Reboot: p.Reboot, By: "automatic"}
		d := &store.Device{ID: dp.ID, Hostname: dp.Hostname}
		if _, err := s.queueTask(ctx, d, "system", "patch.install", "Install %s updates (automatic)", []string{strconv.Itoa(len(ids))}, patchInstallTask{PatchInstall: in}); err != nil {
			s.log.Warn("patch schedule", "device", dp.ID, "err", err)
		}
	}
}
