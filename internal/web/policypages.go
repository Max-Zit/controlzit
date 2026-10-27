package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/store"
)

// ---- the list

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.Policies(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "policies", &Page{Title: "Policies", Nav: "policies", Data: list})
}

// ---- one policy

type policyData struct {
	P           *store.Policy
	S           PolicySettings
	Updates     PatchPolicy // shown values (the policy's or the server's)
	Alerts      AlertRules
	Services    string
	Required    []RequiredApp // with empty rows to add
	Runs        []Automation  // with empty rows to add
	Days        []int
	Hours       []int
	Assigned    []store.Assignment
	Customers   []store.Customer
	Sites       []store.Site
	Devices     []*store.Device
	Packages    []store.SoftwarePackage
	Scripts     []store.LibScript
	Chocolatey  bool
	ScriptNames map[int64]string
}

func (s *Server) policyFor(w http.ResponseWriter, r *http.Request) *store.Policy {
	id, ok := pathID(r, "pid")
	if !ok {
		s.notFound(w, r)
		return nil
	}
	p, err := s.store.Policy(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, r)
		return nil
	}
	if err != nil {
		s.serverError(w, r, err)
		return nil
	}
	return p
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	p := &store.Policy{}
	if r.PathValue("pid") != "" {
		if p = s.policyFor(w, r); p == nil {
			return
		}
	}
	ctx := r.Context()
	d := &policyData{P: p, Days: weekdays, Chocolatey: s.softwareSettings(ctx).Chocolatey, ScriptNames: map[int64]string{}}
	for h := 0; h < 24; h++ {
		d.Hours = append(d.Hours, h)
	}
	_ = json.Unmarshal(p.Settings, &d.S)
	d.Updates = s.Patches(ctx)
	if d.S.Updates != nil {
		d.Updates = *d.S.Updates
	}
	d.Alerts = alertRulesOf(s.Monitoring(ctx))
	if d.S.Alerts != nil {
		d.Alerts = *d.S.Alerts
	}
	d.Services = strings.Join(d.Alerts.WatchServices, "\n")
	if d.S.Software != nil {
		d.Required = append(d.Required, d.S.Software.Required...)
	}
	for i := 0; i < 3; i++ {
		d.Required = append(d.Required, RequiredApp{})
	}
	if d.S.Automations != nil {
		d.Runs = append(d.Runs, d.S.Automations.Runs...)
	}
	for i := 0; i < 2; i++ {
		d.Runs = append(d.Runs, Automation{Minute: 22 * 60})
	}
	var err error
	if p.ID != 0 {
		if d.Assigned, err = s.store.PolicyAssignments(ctx, p.ID); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	u := userFrom(r)
	if d.Customers, err = s.store.Customers(ctx, u); err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, c := range d.Customers {
		sites, err := s.store.Sites(ctx, c.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		d.Sites = append(d.Sites, sites...)
	}
	if d.Devices, err = s.store.Devices(ctx, u, store.DeviceFilter{Limit: 2000}); err != nil {
		s.serverError(w, r, err)
		return
	}
	if d.Packages, err = s.store.SoftwarePackages(ctx); err != nil {
		s.serverError(w, r, err)
		return
	}
	if d.Scripts, err = s.store.LibScripts(ctx); err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, x := range d.Scripts {
		d.ScriptNames[x.ID] = x.Name
	}
	title := p.Name
	if p.ID == 0 {
		title = "New policy"
	}
	s.render(w, r, http.StatusOK, "policy", &Page{Title: title, Nav: "policies", Data: d})
}

// policyForm reads the parts of a policy from the form.
func policyForm(r *http.Request) (PolicySettings, string) {
	var ps PolicySettings
	if r.FormValue("updates_set") == "1" {
		u := PatchPolicy{Mode: r.FormValue("mode"), Reboot: r.FormValue("reboot") == "1"}
		u.Hour, _ = strconv.Atoi(r.FormValue("hour"))
		for _, v := range r.Form["day"] {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 6 && !u.Day(n) {
				u.Days = append(u.Days, n)
			}
		}
		sort.Ints(u.Days)
		if u.Mode != PatchAutoOff && len(u.Days) == 0 {
			return ps, "Choose at least one day."
		}
		ps.Updates = &u
	}
	if r.FormValue("software_set") == "1" {
		sw := &SoftwarePolicy{Required: []RequiredApp{}}
		src, ids, match := r.Form["req_source"], r.Form["req_id"], r.Form["req_match"]
		for i := range src {
			if i >= len(ids) || i >= len(match) {
				break
			}
			a := RequiredApp{Source: src[i], ID: strings.TrimSpace(ids[i]), Match: strings.TrimSpace(match[i])}
			if a.ID == "" && a.Match == "" {
				continue
			}
			sw.Required = append(sw.Required, a)
		}
		ps.Software = sw
	}
	if r.FormValue("alerts_set") == "1" {
		ps.Alerts = &AlertRules{CPUPercent: formInt(r, "cpu_percent"), CPUMinutes: formInt(r, "cpu_minutes"), MemPercent: formInt(r, "mem_percent"),
			MemMinutes: formInt(r, "mem_minutes"), DiskPercent: formInt(r, "disk_percent"), DiskMinFreeGB: formInt(r, "disk_min_free_gb"),
			OfflineMinutes: formInt(r, "offline_minutes"), RebootDays: formInt(r, "reboot_days"), DefenderOff: r.FormValue("defender_off") == "1",
			FirewallOff: r.FormValue("firewall_off") == "1", WatchServices: lines(r.FormValue("watch_services"))}
	}
	if r.FormValue("automations_set") == "1" {
		au := &AutomationPolicy{Runs: []Automation{}}
		for i, v := range r.Form["auto_script"] {
			id, err := strconv.ParseInt(v, 10, 64)
			if err != nil || id <= 0 {
				continue
			}
			a := Automation{ScriptID: id}
			times := r.Form["auto_time"]
			if i < len(times) {
				if t, err := time.Parse("15:04", times[i]); err == nil {
					a.Minute = t.Hour()*60 + t.Minute()
				}
			}
			for _, d := range r.Form["auto_day_"+strconv.Itoa(i)] {
				if n, err := strconv.Atoi(d); err == nil && n >= 0 && n <= 6 && !containsInt(a.Days, n) {
					a.Days = append(a.Days, n)
				}
			}
			sort.Ints(a.Days)
			au.Runs = append(au.Runs, a)
		}
		ps.Automations = au
	}
	if r.FormValue("bitlocker_set") == "1" {
		ps.BitLocker = &BitLockerPolicy{Require: r.FormValue("bitlocker_require") == "1"}
	}
	if err := ps.Validate(); err != nil {
		return ps, err.Error()
	}
	return ps, ""
}

func (s *Server) handlePolicySave(w http.ResponseWriter, r *http.Request) {
	p := &store.Policy{}
	back := "/policies/new"
	if r.PathValue("pid") != "" {
		if p = s.policyFor(w, r); p == nil {
			return
		}
		back = "/policies/" + strconv.FormatInt(p.ID, 10)
	}
	if err := r.ParseForm(); err != nil {
		s.redirect(w, r, back, "Unknown action.")
		return
	}
	p.Name, p.Description = strings.TrimSpace(r.FormValue("name")), strings.TrimSpace(r.FormValue("description"))
	if p.Name == "" || len(p.Name) > 120 || len(p.Description) > 1000 {
		s.redirect(w, r, back, "Enter a name (up to 120 characters).")
		return
	}
	ps, msg := policyForm(r)
	if msg != "" {
		s.redirect(w, r, back, msg)
		return
	}
	raw, err := json.Marshal(ps)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	p.Settings, p.UpdatedBy = raw, s.issuer(r)
	if err := s.store.SavePolicy(r.Context(), p); errors.Is(err, store.ErrConflict) {
		s.redirect(w, r, back, "A policy with this name already exists.")
		return
	} else if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "policy.save", "policy:"+strconv.FormatInt(p.ID, 10), "saved policy %q: %s", p.Name, clip(string(raw), 4000))
	s.redirect(w, r, "/policies/"+strconv.FormatInt(p.ID, 10), "Saved.")
}

func (s *Server) handlePolicyDelete(w http.ResponseWriter, r *http.Request) {
	p := s.policyFor(w, r)
	if p == nil {
		return
	}
	if err := s.store.DeletePolicy(r.Context(), p.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "policy.delete", "policy:"+strconv.FormatInt(p.ID, 10), "deleted policy %q and its assignments", p.Name)
	s.redirect(w, r, "/policies", translate(s.lang(r, userFrom(r)), "Policy %s deleted.", p.Name))
}

// parseTargetRef reads "customer:5", "site:3" or "device:9".
func parseTargetRef(v string) (string, int64, bool) {
	kind, id, ok := strings.Cut(v, ":")
	n, err := strconv.ParseInt(id, 10, 64)
	if !ok || err != nil || n <= 0 || (kind != "customer" && kind != "site" && kind != "device") {
		return "", 0, false
	}
	return kind, n, true
}

func (s *Server) handlePolicyAssign(w http.ResponseWriter, r *http.Request) {
	p := s.policyFor(w, r)
	if p == nil {
		return
	}
	back := "/policies/" + strconv.FormatInt(p.ID, 10)
	kind, id, ok := parseTargetRef(r.FormValue("target"))
	if !ok {
		s.redirect(w, r, back, "Choose a customer, site or device.")
		return
	}
	if !s.targetExists(r, kind, id) {
		s.redirect(w, r, back, "Choose a customer, site or device.")
		return
	}
	if err := s.store.Assign(r.Context(), kind, id, p.ID, s.issuer(r)); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "policy.assign", kind+":"+strconv.FormatInt(id, 10), "assigned policy %q to %s #%d", p.Name, kind, id)
	s.redirect(w, r, back, "Saved.")
}

// targetExists checks that the user may see the customer, site or device.
func (s *Server) targetExists(r *http.Request, kind string, id int64) bool {
	ctx := r.Context()
	switch kind {
	case "customer":
		_, err := s.store.Customer(ctx, id)
		return err == nil && userFrom(r).SeesCustomer(id)
	case "site":
		x, err := s.store.Site(ctx, id)
		return err == nil && userFrom(r).SeesCustomer(x.CustomerID)
	case "device":
		d, err := s.store.Device(ctx, id)
		return err == nil && userFrom(r).SeesCustomer(d.CustomerID)
	}
	return false
}

func (s *Server) handlePolicyUnassign(w http.ResponseWriter, r *http.Request) {
	p := s.policyFor(w, r)
	if p == nil {
		return
	}
	back := "/policies/" + strconv.FormatInt(p.ID, 10)
	kind, id, ok := parseTargetRef(r.FormValue("target"))
	if !ok {
		s.redirect(w, r, back, "Unknown action.")
		return
	}
	if err := s.store.Unassign(r.Context(), kind, id); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "policy.unassign", kind+":"+strconv.FormatInt(id, 10), "removed policy %q from %s #%d", p.Name, kind, id)
	s.redirect(w, r, back, "Saved.")
}

// ---- a device's effective policy

// policyPart is one part of a device's effective policy.
type policyPart struct {
	Name   string // translation key of the part
	Source *policyLevel
}

type devicePolicyData struct {
	D           *store.Device
	Chain       []*policyLevel
	Parts       []policyPart
	Updates     PatchPolicy
	Alerts      MonitoringSettings
	Required    []RequiredAppState
	Runs        []Automation
	ScriptNames map[int64]string
	Assigned    *policyLevel // the device's own assignment
	BitLocker   bool         // the policy requires BitLocker
	Policies    []store.Policy
}

func (s *Server) handleDevicePolicy(w http.ResponseWriter, r *http.Request) {
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	ctx := r.Context()
	pr, err := s.loadPolicies(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	dd := &devicePolicyData{D: d, Chain: pr.chain(d.ID), ScriptNames: map[int64]string{}}
	for _, l := range dd.Chain {
		if l.Level == "device" {
			dd.Assigned = l
		}
	}
	var src *policyLevel
	dd.Updates, src = pr.updates(d.ID, s.Patches(ctx))
	dd.Parts = append(dd.Parts, policyPart{Name: "Windows Update", Source: src})
	sw, src := pr.software(d.ID)
	dd.Parts = append(dd.Parts, policyPart{Name: "Required software", Source: src})
	if sw != nil {
		dd.Required = s.requiredStates(ctx, d, sw)
	}
	dd.Alerts, src = pr.alerts(d.ID, s.Monitoring(ctx))
	dd.Parts = append(dd.Parts, policyPart{Name: "Alert rules", Source: src})
	bl, src := pr.bitlocker(d.ID)
	dd.Parts = append(dd.Parts, policyPart{Name: "BitLocker", Source: src})
	dd.BitLocker = bl != nil && bl.Require
	au, src := pr.automations(d.ID)
	dd.Parts = append(dd.Parts, policyPart{Name: "Automations", Source: src})
	if au != nil {
		dd.Runs = au.Runs
		scripts, err := s.store.LibScripts(ctx)
		if err == nil {
			for _, x := range scripts {
				dd.ScriptNames[x.ID] = x.Name
			}
		}
	}
	if userFrom(r).IsAdmin() {
		if dd.Policies, err = s.store.Policies(ctx); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	s.render(w, r, http.StatusOK, "devicepolicy", &Page{Title: d.Hostname, Nav: "devices", Data: dd})
}

// handleDevicePolicyAssign sets or removes the device's own policy.
func (s *Server) handleDevicePolicyAssign(w http.ResponseWriter, r *http.Request) {
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	back := s.deviceURL(d, "/policy")
	id, err := strconv.ParseInt(r.FormValue("policy"), 10, 64)
	if err != nil || id == 0 {
		if err := s.store.Unassign(r.Context(), "device", d.ID); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.audit(r, "policy.unassign", deviceTarget(d), "removed the device policy of %q", d.Hostname)
		s.redirect(w, r, back, "Saved.")
		return
	}
	p, err := s.store.Policy(r.Context(), id)
	if err != nil {
		s.redirect(w, r, back, "Unknown action.")
		return
	}
	if err := s.store.Assign(r.Context(), "device", d.ID, p.ID, s.issuer(r)); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "policy.assign", deviceTarget(d), "assigned policy %q to %q", p.Name, d.Hostname)
	s.redirect(w, r, back, "Saved.")
}
