package web

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/store"
)

// The device list: search, filters (customer, state, system, alerts,
// vulnerabilities, policy, custom field) and actions on the chosen devices.

type deviceFilters struct {
	Customer   int64
	Status     string // online, offline
	OS         string // windows, linux
	Alerts     bool   // with open alerts
	Vuln       string // critical, high: fixable vulnerabilities of that severity or worse
	Policy     int64
	Field      int64
	FieldValue string
}

func (f deviceFilters) Any() bool { return f != deviceFilters{} }

type devicesData struct {
	Devices   []*store.Device
	Q         string
	Now       time.Time
	F         deviceFilters
	Customers []store.Customer
	Policies  []store.Policy
	Fields    []store.CustomField
	Scripts   []store.LibScript
	Alerts    map[int64]int // open alerts by device
	Vulns     map[int64]int // fixable high or critical vulnerabilities by device
	Total     int           // devices before the filters
}

// Online is used by the device lists.
func (d *devicesData) Online(x *store.Device) bool { return x.Online(d.Now, onlineWindow) }

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := userFrom(r)
	q := strings.TrimSpace(r.FormValue("q"))
	if len(q) > 100 {
		q = q[:100]
	}
	num := func(k string) int64 { n, _ := strconv.ParseInt(r.FormValue(k), 10, 64); return n }
	d := &devicesData{Q: q, Now: s.now(), Alerts: map[int64]int{}, Vulns: map[int64]int{}, F: deviceFilters{
		Customer: num("customer"), Status: r.FormValue("status"), OS: r.FormValue("os"), Alerts: r.FormValue("alerts") == "1",
		Vuln: r.FormValue("vuln"), Policy: num("policy"), Field: num("field"), FieldValue: strings.TrimSpace(r.FormValue("fval")),
	}}
	list, err := s.store.Devices(ctx, u, store.DeviceFilter{Query: q, CustomerID: d.F.Customer, Limit: 2000})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Total = len(list)
	if d.Customers, err = s.store.Customers(ctx, u); err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Fields, _ = s.store.CustomFields(ctx, "device")
	if u.CanWrite() {
		d.Scripts, _ = s.store.LibScripts(ctx)
		all, _ := s.store.Policies(ctx)
		for i := range all {
			if canManagePolicy(u, &all[i]) {
				d.Policies = append(d.Policies, all[i])
			}
		}
	}
	if open, err := s.store.Alerts(ctx, u, store.AlertFilter{Open: true}); err == nil {
		for _, a := range open {
			d.Alerts[a.DeviceID]++
		}
	}
	if vs, err := s.store.DeviceVulns(ctx, 0); err == nil {
		minRank := severityRank["high"]
		if d.F.Vuln == "critical" {
			minRank = severityRank["critical"]
		}
		for _, v := range vs {
			if v.Fix != "none" && severityRank[v.Severity] >= minRank {
				d.Vulns[v.DeviceID]++
			}
		}
	}
	var pr *policyResolver
	if d.F.Policy != 0 {
		pr, _ = s.loadPolicies(ctx)
	}
	var fieldName string
	var values map[int64]map[string]string
	if d.F.Field != 0 {
		for _, f := range d.Fields {
			if f.ID == d.F.Field {
				fieldName = f.Name
			}
		}
		values, _ = s.store.AllFieldValues(ctx, "device")
	}
	keep := func(x *store.Device) bool {
		f := d.F
		switch {
		case f.Status == "online" && !d.Online(x), f.Status == "offline" && d.Online(x),
			f.OS == "windows" && !x.IsWindows(), f.OS == "linux" && x.IsWindows(),
			f.Alerts && d.Alerts[x.ID] == 0,
			f.Vuln != "" && d.Vulns[x.ID] == 0:
			return false
		}
		if f.Policy != 0 {
			if pr == nil || !slices.ContainsFunc(pr.chain(x.ID), func(l *policyLevel) bool { return l.Policy.ID == f.Policy }) {
				return false
			}
		}
		if f.Field != 0 {
			v := values[x.ID][fieldName]
			if v == "" || !strings.Contains(strings.ToLower(v), strings.ToLower(f.FieldValue)) {
				return false
			}
		}
		return true
	}
	for _, x := range list {
		if keep(x) {
			d.Devices = append(d.Devices, x)
		}
	}
	s.render(w, r, http.StatusOK, "devices", &Page{Title: "Devices", Nav: "devices", Data: d})
}

// handleDevicesBulk runs an action on the chosen devices: a library script
// (a job), or a task on each device.
func (s *Server) handleDevicesBulk(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if !u.CanWrite() {
		s.forbidden(w, r)
		return
	}
	ctx := r.Context()
	_ = r.ParseForm()
	back := "/devices"
	if ref := r.FormValue("back"); strings.HasPrefix(ref, "/devices") && !strings.HasPrefix(ref, "//") {
		back = ref
	}
	var devs []*store.Device
	for _, v := range r.Form["ids"] {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || len(devs) >= 2000 {
			continue
		}
		if d, err := s.store.Device(ctx, id); err == nil && u.SeesCustomer(d.CustomerID) {
			devs = append(devs, d)
		}
	}
	if len(devs) == 0 {
		s.redirect(w, r, back, "Choose the devices.")
		return
	}
	action := r.FormValue("action")
	if action == "script" {
		sid, _ := strconv.ParseInt(r.FormValue("script"), 10, 64)
		x, err := s.store.LibScript(ctx, sid)
		if err != nil {
			s.redirect(w, r, back, "Choose a script.")
			return
		}
		ids := make([]int64, len(devs))
		for i, d := range devs {
			ids[i] = d.ID
		}
		j := &store.ScriptJob{ScriptID: &x.ID, Name: x.Name, Shell: x.Shell, Body: x.Body, Timeout: x.Timeout, CreatedBy: u.Username, ExpiresAt: s.now().Add(jobLifetime)}
		if err := s.store.CreateJob(ctx, j, ids); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.audit(r, "job.create", "job:"+strconv.FormatInt(j.ID, 10), "run library script %q on %d devices (device list)", x.Name, len(ids))
		go s.DispatchJobs(context.Background()) // #nosec G118 -- the job runs after the page has answered
		s.redirect(w, r, "/jobs/"+strconv.FormatInt(j.ID, 10), "")
		return
	}
	queued := 0
	for _, d := range devs {
		var err error
		switch action {
		case "scan":
			_, err = s.queueTask(ctx, d, u.Username, "patch.scan", "Search for updates", nil, struct{}{})
		case "security":
			rep, _, e := s.store.PatchReport(ctx, d.ID)
			if e != nil || rep == nil {
				continue
			}
			ids := PatchPolicy{Mode: PatchAutoSecurity}.pick(rep, nil, s.now())
			if len(ids) == 0 {
				continue
			}
			_, err = s.queueTask(ctx, d, u.Username, "patch.install", "Install %s updates", []string{strconv.Itoa(len(ids))},
				patchInstallTask{PatchInstall: proto.PatchInstall{IDs: ids, By: u.Username}})
		case "apps":
			if !d.IsWindows() {
				continue
			}
			_, err = s.queueTask(ctx, d, u.Username, "apps.update", "Update programs", nil, appsUpdateTask{Winget: true})
		case "restart":
			_, err = s.queueTask(ctx, d, u.Username, "power", "Restart in %s seconds", []string{"300"},
				proto.Power{Action: "restart", Delay: 300, Message: "Your administrator restarts this computer in 5 minutes. Save your work."})
		case "inventory":
			if !s.requestInventory(ctx, d.ID) {
				continue
			}
		default:
			s.redirect(w, r, back, "Unknown action.")
			return
		}
		if err != nil {
			s.log.Warn("device list action", "device", d.ID, "action", action, "err", err)
			continue
		}
		queued++
	}
	s.audit(r, "devices.bulk", "devices", "%s on %d of %d chosen devices (device list)", action, queued, len(devs))
	s.redirect(w, r, back, "Started on the chosen devices; each device's Activity shows how it goes.")
}
