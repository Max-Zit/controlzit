package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

// ---- the list

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if !u.CanWrite() {
		s.forbidden(w, r)
		return
	}
	all, err := s.store.Policies(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	list := []store.Policy{}
	for i := range all {
		if canManagePolicy(u, &all[i]) {
			list = append(list, all[i])
		}
	}
	s.render(w, r, http.StatusOK, "policies", &Page{Title: "Policies", Nav: "policies", Data: list})
}

// ---- one policy

type policyData struct {
	P           *store.Policy
	S           PolicySettings
	Updates     PatchPolicy // shown values (the policy's or the built-in ones)
	Alerts      AlertRules
	Services    string
	Apps        AppUpdatePolicy
	Excludes    string
	Maint       []MaintWindow // with an empty row to add
	NewMaint    MaintWindow   // the row "Add a window" adds
	Quiet       bool
	Nets        []NetCheckRule // with an empty row to add
	NewNet      NetCheckRule   // the row "Add a check" adds
	Required    []RequiredApp  // with empty rows to add
	NewApp      RequiredApp    // the row "Add a program" adds
	NewRun      Automation     // the row "Add an automation" adds
	Runs        []Automation   // with empty rows to add
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
	if errors.Is(err, store.ErrNotFound) || err == nil && !canManagePolicy(userFrom(r), p) {
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
	if !userFrom(r).CanWrite() {
		s.forbidden(w, r)
		return
	}
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
	d.Updates = defaultPatchPolicy()
	if d.S.Updates != nil {
		d.Updates = *d.S.Updates
	}
	d.Updates.RestartMode = d.Updates.restartMode()
	if d.Updates.DeadlineDays == 0 {
		d.Updates.DeadlineDays = 3
	}
	d.Alerts = alertRulesOf(defaultMonitoring())
	if d.S.Alerts != nil {
		d.Alerts = *d.S.Alerts
	}
	d.Services = strings.Join(d.Alerts.WatchServices, "\n")
	d.Apps = AppUpdatePolicy{Winget: true, Days: []int{3}, Hour: 12}
	if d.S.AppUpdates != nil {
		d.Apps = *d.S.AppUpdates
	}
	d.Excludes = strings.Join(d.Apps.Exclude, "\n")
	if d.S.Maintenance != nil {
		d.Maint, d.Quiet = append(d.Maint, d.S.Maintenance.Windows...), d.S.Maintenance.Quiet
	}
	if len(d.Maint) == 0 {
		d.Maint = append(d.Maint, MaintWindow{Days: []int{6}, Start: 22 * 60, Hours: 4})
	}
	for i := range d.Maint {
		d.Maint[i].Key = "w" + strconv.Itoa(i)
	}
	d.NewMaint = MaintWindow{Key: "__KEY__", Start: 22 * 60, Hours: 4}
	if d.S.NetChecks != nil {
		d.Nets = append(d.Nets, d.S.NetChecks.Checks...)
	}
	d.NewNet = NetCheckRule{NetCheck: proto.NetCheck{Kind: proto.NetPing}, FailMinutes: 3}
	if len(d.Nets) == 0 {
		d.Nets = append(d.Nets, d.NewNet)
	}
	if d.S.Software != nil {
		d.Required = append(d.Required, d.S.Software.Required...)
	}
	if len(d.Required) == 0 {
		d.Required = append(d.Required, RequiredApp{Source: "winget"})
	}
	d.NewApp = RequiredApp{Source: "winget"}
	if d.S.Automations != nil {
		d.Runs = append(d.Runs, d.S.Automations.Runs...)
	}
	if len(d.Runs) == 0 {
		d.Runs = append(d.Runs, Automation{Minute: 22 * 60})
	}
	for i := range d.Runs {
		d.Runs[i].Key = "r" + strconv.Itoa(i)
	}
	d.NewRun = Automation{Key: "__KEY__", Minute: 22 * 60}
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
	// A customer's policy is assigned only within that customer.
	if p.CustomerID != nil {
		cid := *p.CustomerID
		d.Customers = slices.DeleteFunc(d.Customers, func(c store.Customer) bool { return c.ID != cid })
		d.Sites = slices.DeleteFunc(d.Sites, func(x store.Site) bool { return x.CustomerID != cid })
		d.Devices = slices.DeleteFunc(d.Devices, func(x *store.Device) bool { return x.CustomerID != cid })
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
		u := PatchPolicy{Mode: r.FormValue("mode"), RestartMode: r.FormValue("restart_mode"), InWindow: r.FormValue("when") == "window",
			DelayDays: formInt(r, "delay_days"), DeadlineDays: formInt(r, "deadline_days")}
		u.Reboot = u.RestartMode == RestartAuto // for servers that read the older field
		u.Hour, _ = strconv.Atoi(r.FormValue("hour"))
		u.Days = formDays(r, "day")
		if u.Mode != PatchAutoOff && !u.InWindow && len(u.Days) == 0 {
			return ps, "Choose at least one day."
		}
		ps.Updates = &u
	}
	if r.FormValue("apps_set") == "1" {
		a := &AppUpdatePolicy{Winget: r.FormValue("apps_winget") == "1", Choco: r.FormValue("apps_choco") == "1",
			InWindow: r.FormValue("apps_when") == "window", DelayDays: formInt(r, "apps_delay"), Exclude: lines(r.FormValue("apps_exclude"))}
		a.Hour, _ = strconv.Atoi(r.FormValue("apps_hour"))
		a.Days = formDays(r, "apps_day")
		ps.AppUpdates = a
	}
	if r.FormValue("net_set") == "1" {
		n := &NetCheckPolicy{Checks: []NetCheckRule{}}
		names, kinds, targets, ports, mins := r.Form["net_name"], r.Form["net_kind"], r.Form["net_target"], r.Form["net_port"], r.Form["net_minutes"]
		for i := range names {
			if i >= len(kinds) || i >= len(targets) || i >= len(ports) || i >= len(mins) {
				break
			}
			c := NetCheckRule{NetCheck: proto.NetCheck{Name: strings.TrimSpace(names[i]), Kind: kinds[i], Target: strings.TrimSpace(targets[i])}}
			if c.Name == "" && c.Target == "" {
				continue
			}
			c.Port, _ = strconv.Atoi(ports[i])
			c.FailMinutes, _ = strconv.Atoi(mins[i])
			n.Checks = append(n.Checks, c)
		}
		ps.NetChecks = n
	}
	if r.FormValue("maint_set") == "1" {
		m := &MaintenancePolicy{Windows: []MaintWindow{}, Quiet: r.FormValue("maint_quiet") == "1"}
		days := keyedDays(r, "maint_day")
		keys, starts, hours := r.Form["maint_key"], r.Form["maint_time"], r.Form["maint_hours"]
		for i, k := range keys {
			if i >= len(starts) || i >= len(hours) {
				break
			}
			t, err := time.Parse("15:04", starts[i])
			if err != nil {
				continue
			}
			w := MaintWindow{Days: days[k], Start: t.Hour()*60 + t.Minute()}
			w.Hours, _ = strconv.Atoi(hours[i])
			sort.Ints(w.Days)
			m.Windows = append(m.Windows, w)
		}
		ps.Maintenance = m
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
			FirewallOff: r.FormValue("firewall_off") == "1", WatchServices: lines(r.FormValue("watch_services")), DiskHealthOff: r.FormValue("disk_health") != "1"}
	}
	if r.FormValue("automations_set") == "1" {
		au := &AutomationPolicy{Runs: []Automation{}}
		days := keyedDays(r, "auto_day")
		keys := r.Form["auto_key"]
		for i, v := range r.Form["auto_script"] {
			id, err := strconv.ParseInt(v, 10, 64)
			if err != nil || id <= 0 {
				continue
			}
			a := Automation{ScriptID: id}
			if i < len(keys) {
				a.Days = days[keys[i]]
			}
			times := r.Form["auto_time"]
			if i < len(times) {
				if t, err := time.Parse("15:04", times[i]); err == nil {
					a.Minute = t.Hour()*60 + t.Minute()
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
	u := userFrom(r)
	if !u.CanWrite() {
		s.forbidden(w, r)
		return
	}
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
	if p.ID == 0 {
		// The owner is chosen once: a customer, or (administrators) the whole server.
		if cid, _ := strconv.ParseInt(r.FormValue("customer"), 10, 64); cid > 0 {
			if _, err := s.store.Customer(r.Context(), cid); err != nil || !u.SeesCustomer(cid) {
				s.redirect(w, r, back, "Choose the customer of the policy.")
				return
			}
			p.CustomerID = &cid
		} else if !u.IsAdmin() {
			s.redirect(w, r, back, "Choose the customer of the policy.")
			return
		}
	}
	var old PolicySettings
	_ = json.Unmarshal(p.Settings, &old)
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
	if !u.IsAdmin() {
		ps.BitLocker = old.BitLocker // BitLocker is for administrators
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
	s.policiesChanged()
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
	s.policiesChanged()
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
	if !s.mayAssign(r.Context(), userFrom(r), p, kind, id) {
		s.redirect(w, r, back, "Choose a customer, site or device of this policy.")
		return
	}
	if err := s.store.Assign(r.Context(), kind, id, p.ID, s.issuer(r)); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "policy.assign", kind+":"+strconv.FormatInt(id, 10), "assigned policy %q to %s #%d", p.Name, kind, id)
	s.policiesChanged()
	s.redirect(w, r, back, "Saved.")
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
	if !s.mayAssign(r.Context(), userFrom(r), p, kind, id) {
		s.redirect(w, r, back, "Unknown action.")
		return
	}
	if err := s.store.Unassign(r.Context(), kind, id); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "policy.unassign", kind+":"+strconv.FormatInt(id, 10), "removed policy %q from %s #%d", p.Name, kind, id)
	s.policiesChanged()
	s.redirect(w, r, back, "Saved.")
}

// ---- a device's effective policy

// policyPart is one part of a device's effective policy.
type policyPart struct {
	Name   string // translation key of the part
	Source *policyLevel
}

type devicePolicyData struct {
	CanChange   bool // the user may set the device's own policy
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
	Apps        *AppUpdatePolicy
	Maint       *MaintenancePolicy
	InWindow    bool                  // a maintenance window is open now
	Restart     *store.RestartRequest // a restart the policy asks for
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
	dd.Updates, src = pr.updates(d.ID, defaultPatchPolicy())
	dd.Updates.RestartMode = dd.Updates.restartMode()
	dd.Parts = append(dd.Parts, policyPart{Name: "Windows Update", Source: src})
	sw, src := pr.software(d.ID)
	dd.Parts = append(dd.Parts, policyPart{Name: "Required software", Source: src})
	if sw != nil {
		dd.Required = s.requiredStates(ctx, d, sw)
	}
	dd.Alerts, src = pr.alerts(d.ID, builtinAlerts(s.Monitoring(ctx)))
	dd.Parts = append(dd.Parts, policyPart{Name: "Alert rules", Source: src})
	bl, src := pr.bitlocker(d.ID)
	dd.Parts = append(dd.Parts, policyPart{Name: "BitLocker", Source: src})
	dd.BitLocker = bl != nil && bl.Require
	au, src := pr.automations(d.ID)
	dd.Parts = append(dd.Parts, policyPart{Name: "Automations", Source: src})
	dd.Apps, src = pr.appUpdates(d.ID)
	dd.Parts = append(dd.Parts, policyPart{Name: "Program updates", Source: src})
	dd.Maint, src = pr.maintenance(d.ID)
	dd.Parts = append(dd.Parts, policyPart{Name: "Maintenance windows", Source: src})
	_, src = pr.netChecks(d.ID)
	dd.Parts = append(dd.Parts, policyPart{Name: "Network checks", Source: src})
	dd.InWindow = dd.Maint.active(s.now().Local())
	if reqs, err := s.store.RestartRequests(ctx); err == nil {
		if q, ok := reqs[d.ID]; ok {
			dd.Restart = &q
		}
	}
	if au != nil {
		dd.Runs = au.Runs
		scripts, err := s.store.LibScripts(ctx)
		if err == nil {
			for _, x := range scripts {
				dd.ScriptNames[x.ID] = x.Name
			}
		}
	}
	if u := userFrom(r); u.CanWrite() {
		all, err := s.store.Policies(ctx)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		// The policies this user may give this device.
		for i := range all {
			p := &all[i]
			if canManagePolicy(u, p) && (p.CustomerID == nil || *p.CustomerID == d.CustomerID) {
				dd.Policies = append(dd.Policies, *p)
			}
		}
		dd.CanChange = dd.Assigned == nil || canManagePolicy(u, dd.Assigned.Policy)
	}
	s.render(w, r, http.StatusOK, "devicepolicy", &Page{Title: d.Hostname, Nav: "devices", Data: dd})
}

// handleDevicePolicyAssign sets or removes the device's own policy.
func (s *Server) handleDevicePolicyAssign(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r) // technicians and administrators
	if d == nil {
		return
	}
	u := userFrom(r)
	back := s.deviceURL(d, "/policy")
	id, err := strconv.ParseInt(r.FormValue("policy"), 10, 64)
	if err != nil || id == 0 {
		// Removing needs the right to manage the policy the device has.
		if pr, err := s.loadPolicies(r.Context()); err == nil {
			for _, l := range pr.chain(d.ID) {
				if l.Level == "device" && !canManagePolicy(u, l.Policy) {
					s.redirect(w, r, back, "Unknown action.")
					return
				}
			}
		}
		if err := s.store.Unassign(r.Context(), "device", d.ID); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.audit(r, "policy.unassign", deviceTarget(d), "removed the device policy of %q", d.Hostname)
		s.policiesChanged()
		s.redirect(w, r, back, "Saved.")
		return
	}
	p, err := s.store.Policy(r.Context(), id)
	if err != nil || !s.mayAssign(r.Context(), u, p, "device", d.ID) {
		s.redirect(w, r, back, "Unknown action.")
		return
	}
	if err := s.store.Assign(r.Context(), "device", d.ID, p.ID, s.issuer(r)); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "policy.assign", deviceTarget(d), "assigned policy %q to %q", p.Name, d.Hostname)
	s.policiesChanged()
	s.redirect(w, r, back, "Saved.")
}

// ---- who may manage which policy

// canManagePolicy: administrators manage every policy; technicians the
// policies of their customers.
func canManagePolicy(u *store.User, p *store.Policy) bool {
	if u.IsAdmin() {
		return true
	}
	return u.CanWrite() && p.CustomerID != nil && u.SeesCustomer(*p.CustomerID)
}

// targetCustomer is the customer of a customer, site or device.
func (s *Server) targetCustomer(ctx context.Context, kind string, id int64) (int64, bool) {
	switch kind {
	case "customer":
		if _, err := s.store.Customer(ctx, id); err == nil {
			return id, true
		}
	case "site":
		if x, err := s.store.Site(ctx, id); err == nil {
			return x.CustomerID, true
		}
	case "device":
		if d, err := s.store.Device(ctx, id); err == nil {
			return d.CustomerID, true
		}
	}
	return 0, false
}

// mayAssign reports whether the user may give policy p to the target: the
// user sees the target, and a customer's policy stays within its customer.
func (s *Server) mayAssign(ctx context.Context, u *store.User, p *store.Policy, kind string, id int64) bool {
	cid, ok := s.targetCustomer(ctx, kind, id)
	if !ok || !u.SeesCustomer(cid) || !canManagePolicy(u, p) {
		return false
	}
	return p.CustomerID == nil || *p.CustomerID == cid
}

// policiesChanged applies changed alert rules at once; the other parts
// follow their own schedules.
func (s *Server) policiesChanged() {
	go s.CheckAlerts(context.Background()) // #nosec G118 -- runs after the response; own work
}

// formDays reads the checked weekdays of a field.
func formDays(r *http.Request, name string) []int {
	var out []int
	for _, v := range r.Form[name] {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 6 && !containsInt(out, n) {
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}

// keyedDays reads weekdays checked per form row ("rowkey:day").
func keyedDays(r *http.Request, name string) map[string][]int {
	days := map[string][]int{}
	for _, v := range r.Form[name] {
		k, d, ok := strings.Cut(v, ":")
		if n, err := strconv.Atoi(d); ok && err == nil && n >= 0 && n <= 6 && !containsInt(days[k], n) {
			days[k] = append(days[k], n)
		}
	}
	return days
}
