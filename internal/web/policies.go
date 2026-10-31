package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/store"
)

// Policies: named settings for Windows Update, required software, alert
// rules and scheduled automations, assigned to customers, sites or devices.
// Each part of a policy is either set or left to a less specific policy;
// for each part the most specific assignment that sets it wins (device,
// site, customer), and the server's own settings apply when none does.

// PolicySettings are the parts of a policy; nil means "not set here".
type PolicySettings struct {
	Updates     *PatchPolicy       `json:"updates,omitempty"`
	Software    *SoftwarePolicy    `json:"software,omitempty"`
	Alerts      *AlertRules        `json:"alerts,omitempty"`
	Automations *AutomationPolicy  `json:"automations,omitempty"`
	BitLocker   *BitLockerPolicy   `json:"bitlocker,omitempty"`
	AppUpdates  *AppUpdatePolicy   `json:"app_updates,omitempty"`
	Maintenance *MaintenancePolicy `json:"maintenance,omitempty"`
	NetChecks   *NetCheckPolicy    `json:"net_checks,omitempty"`
	Monitors    *MonitorPolicy     `json:"monitors,omitempty"`
}

// SoftwarePolicy lists the programs a device must have; missing ones are
// installed by the server.
type SoftwarePolicy struct {
	Required []RequiredApp `json:"required"`
	Blocked  []BlockedApp  `json:"blocked,omitempty"`
}

// BlockedApp is a program the devices must not have: it opens an alert and,
// with Remove, is uninstalled silently.
type BlockedApp struct {
	Match  string `json:"match"` // part of the installed program's name
	Remove bool   `json:"remove,omitempty"`
}

// RequiredApp is one required program: where it is installed from and how
// it is recognized among the installed programs.
type RequiredApp struct {
	Source string `json:"source"` // library, winget, choco
	ID     string `json:"id"`     // library package ID, winget or Chocolatey package ID
	Match  string `json:"match"`  // part of the installed program's name
}

// Key identifies the app for repeated attempts.
func (a RequiredApp) Key() string { return a.Source + ":" + strings.ToLower(a.ID) }

// AlertRules are the thresholds of the alert rules (email settings stay
// those of the server).
type AlertRules struct {
	CPUPercent     int      `json:"cpu_percent"`
	CPUMinutes     int      `json:"cpu_minutes"`
	MemPercent     int      `json:"mem_percent"`
	MemMinutes     int      `json:"mem_minutes"`
	DiskPercent    int      `json:"disk_percent"`
	DiskMinFreeGB  int      `json:"disk_min_free_gb"`
	OfflineMinutes int      `json:"offline_minutes"`
	RebootDays     int      `json:"reboot_days"`
	DefenderOff    bool     `json:"defender_off"`
	FirewallOff    bool     `json:"firewall_off"`
	WatchServices  []string `json:"watch_services"`
	DiskHealthOff  bool     `json:"disk_health_off,omitempty"` // no alerts for disk and RAID problems
	VulnAlerts     bool     `json:"vuln_alerts,omitempty"`     // alert on critical vulnerabilities
	DiskFullDays   int      `json:"disk_full_days,omitempty"`  // alert when a disk will be full within this many days
}

func alertRulesOf(m MonitoringSettings) AlertRules {
	return AlertRules{CPUPercent: m.CPUPercent, CPUMinutes: m.CPUMinutes, MemPercent: m.MemPercent, MemMinutes: m.MemMinutes,
		DiskPercent: m.DiskPercent, DiskMinFreeGB: m.DiskMinFreeGB, OfflineMinutes: m.OfflineMinutes, RebootDays: m.RebootDays,
		DefenderOff: m.DefenderOff, FirewallOff: m.FirewallOff, WatchServices: m.WatchServices, DiskHealthOff: m.DiskHealthOff, VulnAlerts: m.VulnAlerts,
		DiskFullDays: m.DiskFullDays}
}

// apply puts the thresholds into the server's monitoring settings.
func (a AlertRules) apply(m MonitoringSettings) MonitoringSettings {
	m.CPUPercent, m.CPUMinutes, m.MemPercent, m.MemMinutes = a.CPUPercent, a.CPUMinutes, a.MemPercent, a.MemMinutes
	m.DiskPercent, m.DiskMinFreeGB, m.OfflineMinutes, m.RebootDays = a.DiskPercent, a.DiskMinFreeGB, a.OfflineMinutes, a.RebootDays
	m.DefenderOff, m.FirewallOff, m.WatchServices, m.DiskHealthOff, m.VulnAlerts = a.DefenderOff, a.FirewallOff, a.WatchServices, a.DiskHealthOff, a.VulnAlerts
	m.DiskFullDays = a.DiskFullDays
	return m
}

// AutomationPolicy runs library scripts on the devices on set days.
type AutomationPolicy struct {
	Runs []Automation `json:"runs"`
}

// Automation is one scheduled script.
type Automation struct {
	ScriptID int64  `json:"script_id"`
	Days     []int  `json:"days"`   // time.Weekday values
	Minute   int    `json:"minute"` // of the day, server time
	Key      string `json:"-"`      // the row of the form (days belong to it)
}

// Time is the time of day as HH:MM.
func (a Automation) Time() string { return fmt.Sprintf("%02d:%02d", a.Minute/60, a.Minute%60) }

// Validate checks a policy's settings.
func (p *PolicySettings) Validate() error {
	if u := p.Updates; u != nil {
		if u.Mode != PatchAutoOff && u.Mode != PatchAutoSecurity && u.Mode != PatchAutoAll {
			return errors.New("unknown Windows Update mode")
		}
		if u.Hour < 0 || u.Hour > 23 || len(u.Days) > 7 {
			return errors.New("choose the days and an hour 0–23")
		}
		if u.DelayDays < 0 || u.DelayDays > 60 || u.DeadlineDays < 0 || u.DeadlineDays > 30 {
			return errors.New("the update ring delay must be 0–60 days and the restart deadline 0–30 days")
		}
		if m := u.RestartMode; m != "" && m != RestartNever && m != RestartAuto && m != RestartDeadline {
			return errors.New("unknown restart mode")
		}
	}
	if sw := p.Software; sw != nil {
		if len(sw.Blocked) > 50 {
			return errors.New("at most 50 blocked programs")
		}
		for _, b := range sw.Blocked {
			if n := len(strings.TrimSpace(b.Match)); n < 3 || n > 100 {
				return errors.New("each blocked program needs 3–100 characters of its installed name")
			}
		}
		if len(sw.Required) > 50 {
			return errors.New("at most 50 required programs")
		}
		for _, a := range sw.Required {
			ok := false
			switch a.Source {
			case "library":
				_, err := strconv.ParseInt(a.ID, 10, 64)
				ok = err == nil
			case "winget":
				ok = proto.ValidWingetID(a.ID)
			case "choco":
				ok = proto.ValidChocoID(a.ID)
			}
			if !ok || len(strings.TrimSpace(a.Match)) < 2 || len(a.Match) > 100 {
				return errors.New("each required program needs a source, a package and at least 2 characters of its installed name")
			}
		}
	}
	if a := p.Alerts; a != nil {
		m := a.apply(defaultMonitoring())
		if err := m.Validate(); err != nil {
			return err
		}
	}
	if a := p.AppUpdates; a != nil {
		if err := a.validate(); err != nil {
			return err
		}
	}
	if m := p.Maintenance; m != nil {
		if err := m.validate(); err != nil {
			return err
		}
	}
	if n := p.NetChecks; n != nil {
		if err := n.validate(); err != nil {
			return err
		}
	}
	if m := p.Monitors; m != nil {
		if err := m.validate(); err != nil {
			return err
		}
	}
	if au := p.Automations; au != nil {
		if len(au.Runs) > 20 {
			return errors.New("at most 20 automations")
		}
		for _, r := range au.Runs {
			if r.ScriptID <= 0 || len(r.Days) == 0 || r.Minute < 0 || r.Minute >= 1440 {
				return errors.New("each automation needs a script, at least one day and the time")
			}
		}
	}
	return nil
}

// ---- resolving the policies of a device

// policyLevel is a policy assigned at one level of a device.
type policyLevel struct {
	Level    string // device, site, customer
	Policy   *store.Policy
	Settings PolicySettings
}

// policyResolver answers which policy sets which part for every device.
type policyResolver struct {
	byTarget map[string]*policyLevel
	scopes   map[int64]store.DeviceScope
}

// policyCache keeps the resolver the background loops share; it is loaded
// again when the store reports a change of policies, assignments or
// devices, and at the latest after policyCacheFor (device OS changes).
type policyCache struct {
	mu      sync.Mutex
	pr      *policyResolver
	version uint64
	at      time.Time
}

const policyCacheFor = time.Minute

// cachedPolicies is loadPolicies for background work, which asks for the
// policies many times a minute. Callers must not change the resolver.
func (s *Server) cachedPolicies(ctx context.Context) (*policyResolver, error) {
	s.policies.mu.Lock()
	defer s.policies.mu.Unlock()
	v := s.store.ScopeVersion()
	if c := &s.policies; c.pr != nil && c.version == v && time.Since(c.at) < policyCacheFor {
		return c.pr, nil
	}
	pr, err := s.loadPolicies(ctx)
	if err != nil {
		return nil, err
	}
	s.policies.pr, s.policies.version, s.policies.at = pr, v, time.Now()
	return pr, nil
}

func (s *Server) loadPolicies(ctx context.Context) (*policyResolver, error) {
	list, err := s.store.Policies(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[int64]*store.Policy{}
	settings := map[int64]PolicySettings{}
	for i := range list {
		p := &list[i]
		byID[p.ID] = p
		var ps PolicySettings
		_ = json.Unmarshal(p.Settings, &ps)
		settings[p.ID] = ps
	}
	as, err := s.store.Assignments(ctx)
	if err != nil {
		return nil, err
	}
	pr := &policyResolver{byTarget: map[string]*policyLevel{}, scopes: map[int64]store.DeviceScope{}}
	for _, a := range as {
		if p := byID[a.PolicyID]; p != nil {
			pr.byTarget[a.TargetType+":"+strconv.FormatInt(a.TargetID, 10)] = &policyLevel{Level: a.TargetType, Policy: p, Settings: settings[p.ID]}
		}
	}
	scopes, err := s.store.DeviceScopes(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range scopes {
		pr.scopes[d.DeviceID] = d
	}
	return pr, nil
}

// chain lists the policies of a device, most specific first.
func (pr *policyResolver) chain(deviceID int64) []*policyLevel {
	sc, ok := pr.scopes[deviceID]
	if !ok {
		return nil
	}
	var out []*policyLevel
	for _, k := range []string{"device:" + strconv.FormatInt(deviceID, 10), "site:" + strconv.FormatInt(sc.SiteID, 10), "customer:" + strconv.FormatInt(sc.CustomerID, 10)} {
		if l := pr.byTarget[k]; l != nil {
			out = append(out, l)
		}
	}
	return out
}

// part returns the most specific level that sets a part (nil: none).
func (pr *policyResolver) part(deviceID int64, set func(*PolicySettings) bool) *policyLevel {
	for _, l := range pr.chain(deviceID) {
		if set(&l.Settings) {
			return l
		}
	}
	return nil
}

func (pr *policyResolver) updates(deviceID int64, def PatchPolicy) (PatchPolicy, *policyLevel) {
	if l := pr.part(deviceID, func(p *PolicySettings) bool { return p.Updates != nil }); l != nil {
		return *l.Settings.Updates, l
	}
	return def, nil
}

func (pr *policyResolver) alerts(deviceID int64, def MonitoringSettings) (MonitoringSettings, *policyLevel) {
	if l := pr.part(deviceID, func(p *PolicySettings) bool { return p.Alerts != nil }); l != nil {
		return l.Settings.Alerts.apply(def), l
	}
	return def, nil
}

func (pr *policyResolver) software(deviceID int64) (*SoftwarePolicy, *policyLevel) {
	if l := pr.part(deviceID, func(p *PolicySettings) bool { return p.Software != nil }); l != nil {
		return l.Settings.Software, l
	}
	return nil, nil
}

func (pr *policyResolver) automations(deviceID int64) (*AutomationPolicy, *policyLevel) {
	if l := pr.part(deviceID, func(p *PolicySettings) bool { return p.Automations != nil }); l != nil {
		return l.Settings.Automations, l
	}
	return nil, nil
}

// ---- required software

const (
	// requiredRetry is how long the server waits before it tries again to
	// install a required program that is still missing.
	requiredRetry = 6 * time.Hour
	// requiredEvery is how often the server checks the required software.
	requiredEvery = 5 * time.Minute
)

// appInstalled reports whether the inventory lists a program whose name
// contains match.
func appInstalled(inv *proto.Inventory, match string) bool {
	if inv == nil {
		return false
	}
	m := strings.ToLower(strings.TrimSpace(match))
	for _, sw := range inv.Software {
		if strings.Contains(strings.ToLower(sw.Name), m) {
			return true
		}
	}
	return false
}

// RequiredAppState is the state of one required program on a device.
type RequiredAppState struct {
	App       RequiredApp
	Name      string // library package name, or the package ID
	Installed bool
	Tried     time.Time // last installation the policy started
}

func (s *Server) requiredStates(ctx context.Context, d *store.Device, sw *SoftwarePolicy) []RequiredAppState {
	var out []RequiredAppState
	for _, a := range sw.Required {
		st := RequiredAppState{App: a, Name: a.ID, Installed: appInstalled(d.Inventory, a.Match)}
		if a.Source == "library" {
			if id, err := strconv.ParseInt(a.ID, 10, 64); err == nil {
				if p, err := s.store.SoftwarePackage(ctx, id); err == nil {
					st.Name = strings.TrimSpace(p.Name + " " + p.Version)
				}
			}
		}
		st.Tried, _ = s.store.Marked(ctx, requiredKey(d.ID, a))
		out = append(out, st)
	}
	return out
}

func requiredKey(deviceID int64, a RequiredApp) string {
	return "required:" + strconv.FormatInt(deviceID, 10) + ":" + a.Key()
}

// RunRequiredSoftware installs the required programs that are missing on
// connected Windows devices (monitor loop, every requiredEvery).
func (s *Server) RunRequiredSoftware(ctx context.Context) {
	pr, err := s.cachedPolicies(ctx)
	if err != nil {
		s.log.Warn("policies: cannot load", "err", err)
		return
	}
	for id, sc := range pr.scopes {
		sw, l := pr.software(id)
		if sw == nil || len(sw.Required)+len(sw.Blocked) == 0 || !s.Connected(id) || (sc.OS != "" && !strings.Contains(sc.OS, "Windows")) {
			continue
		}
		d, err := s.store.Device(ctx, id)
		if err != nil || d.Inventory == nil {
			continue
		}
		s.removeBlocked(ctx, d, sw, l.Policy.Name)
		for _, a := range sw.Required {
			if appInstalled(d.Inventory, a.Match) {
				continue
			}
			key := requiredKey(id, a)
			if t, err := s.store.Marked(ctx, key); err != nil || s.now().Sub(t) < requiredRetry {
				continue
			}
			if err := s.installRequired(ctx, d, a, l.Policy.Name); err != nil {
				s.log.Warn("policies: cannot install a required program", "device", id, "app", a.Key(), "err", err)
				continue
			}
			_ = s.store.Mark(ctx, key)
		}
	}
}

// installRequired starts the installation of a required program.
func (s *Server) installRequired(ctx context.Context, d *store.Device, a RequiredApp, policy string) error {
	by := "policy " + policy
	back := s.deviceURL(d, "/policy")
	switch a.Source {
	case "library":
		id, err := strconv.ParseInt(a.ID, 10, 64)
		if err != nil {
			return err
		}
		p, err := s.store.SoftwarePackage(ctx, id)
		if err != nil {
			return err
		}
		if _, err := s.packageJob(ctx, by, p, []int64{d.ID}); err != nil {
			return err
		}
		go s.DispatchJobs(context.Background()) // #nosec G118 -- the job runs after this check
	case "winget":
		if _, err := s.queueTask(ctx, d, by, "winget", "Install %s (winget)", []string{a.ID}, wingetTask{Winget: proto.Winget{Action: proto.WingetInstall, ID: a.ID}, Back: back}); err != nil {
			return err
		}
	case "choco":
		if _, err := s.queueTask(ctx, d, by, "choco", "Install %s (Chocolatey)", []string{a.ID}, chocoTask{Choco: proto.Choco{Action: proto.ChocoInstall, ID: a.ID}, Back: back}); err != nil {
			return err
		}
	default:
		return errors.New("unknown source")
	}
	_ = s.store.Audit(ctx, "system", "", "policy.install", deviceTarget(d), fmt.Sprintf("%s: required program %s (%s) is missing on %q; installation started", by, a.ID, a.Source, d.Hostname))
	return nil
}

// ---- automations

// RunPolicyAutomations starts the scheduled scripts of policies that are due
// (monitor loop, every minute): one job per automation and time slot, for
// the devices whose automations come from that policy.
func (s *Server) RunPolicyAutomations(ctx context.Context) {
	pr, err := s.cachedPolicies(ctx)
	if err != nil {
		return
	}
	now := s.now().Local()
	minute := now.Hour()*60 + now.Minute()
	slot := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), 0, 0, now.Location())
	type run struct {
		policy  *store.Policy
		auto    Automation
		index   int
		devices []int64
	}
	runs := map[string]*run{}
	for id := range pr.scopes {
		au, l := pr.automations(id)
		if au == nil {
			continue
		}
		for i, a := range au.Runs {
			if a.Minute > minute || minute-a.Minute > 10 || !containsInt(a.Days, int(now.Weekday())) {
				continue
			}
			k := strconv.FormatInt(l.Policy.ID, 10) + ":" + strconv.Itoa(i)
			if runs[k] == nil {
				runs[k] = &run{policy: l.Policy, auto: a, index: i}
			}
			runs[k].devices = append(runs[k].devices, id)
		}
	}
	for k, r := range runs {
		due := slot.Add(-time.Duration(minute-r.auto.Minute) * time.Minute)
		if ok, err := s.store.MarkOnce(ctx, "automation:"+k+":"+strconv.FormatInt(r.auto.ScriptID, 10), due); err != nil || !ok {
			continue
		}
		x, err := s.store.LibScript(ctx, r.auto.ScriptID)
		if err != nil {
			continue
		}
		sid := x.ID
		j := &store.ScriptJob{ScriptID: &sid, Name: x.Name, Shell: x.Shell, Body: x.Body, Timeout: x.Timeout,
			CreatedBy: "policy " + r.policy.Name, ExpiresAt: s.now().Add(jobLifetime)}
		if err := s.store.CreateJob(ctx, j, r.devices); err != nil {
			s.log.Warn("policies: cannot create a job", "policy", r.policy.ID, "err", err)
			continue
		}
		_ = s.store.Audit(ctx, "system", "", "job.create", "job:"+strconv.FormatInt(j.ID, 10),
			fmt.Sprintf("policy %q runs library script %q on %d devices", r.policy.Name, x.Name, len(r.devices)))
	}
	if len(runs) > 0 {
		s.DispatchJobs(ctx)
	}
}
