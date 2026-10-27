package web

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/controlzit/internal/store"
)

// Script library: saved scripts that run on many devices at once (jobs) or
// on a schedule. Devices that are offline run a job when they connect, until
// it expires. Only administrators edit the library and the schedules (a
// script runs as SYSTEM on every device it targets); technicians run library
// scripts on the devices of their customers.

const (
	jobLifetime = 24 * time.Hour
	// jobParallel limits scripts running at once for jobs.
	jobParallel = 32
)

func (h *hub) connectedIDs() []int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]int64, 0, len(h.conns))
	for id := range h.conns {
		out = append(out, id)
	}
	return out
}

type jobRunner struct {
	once sync.Once
	sem  chan struct{}
}

// DispatchJobs starts the pending job runs of connected devices. It is
// called when a job is created, when an agent connects and every minute.
func (s *Server) DispatchJobs(ctx context.Context) {
	s.jobs.once.Do(func() { s.jobs.sem = make(chan struct{}, jobParallel) })
	if err := s.store.ExpireJobs(ctx, false); err != nil {
		s.log.Warn("jobs: cannot expire", "err", err)
	}
	ids := s.hub.connectedIDs()
	if len(ids) == 0 {
		return
	}
	runs, err := s.store.ClaimJobRuns(ctx, ids)
	if err != nil {
		s.log.Warn("jobs: cannot claim runs", "err", err)
		return
	}
	for _, jr := range runs {
		go s.runJob(jr) // #nosec G118 -- a job run outlives the request that started it; own timeout
	}
}

func (s *Server) runJob(jr store.JobRun) {
	s.jobs.sem <- struct{}{}
	defer func() { <-s.jobs.sem }()
	base, cancelTask := context.WithCancelCause(context.Background())
	defer cancelTask(nil)
	ctx, cancel := context.WithTimeout(base, time.Duration(jr.Timeout)*time.Second+2*actionTimeout)
	defer cancel()
	d, err := s.store.Device(ctx, jr.DeviceID)
	if err != nil {
		_ = s.store.FinishJobRun(ctx, jr.JobID, jr.DeviceID, "failed", nil)
		return
	}
	jobID := jr.JobID
	// The run is a task of the device too: visible under Activity, and it
	// can be stopped there.
	title := "Job #%s: %s"
	if jr.Shell == "package" {
		title = "Job #%s: install %s"
	}
	task := &store.DeviceTask{DeviceID: d.ID, Kind: "job", Title: title, TitleArgs: []string{strconv.FormatInt(jobID, 10), jr.Name}, CreatedBy: jr.CreatedBy, JobID: &jobID}
	if err := s.store.AddRunningTask(ctx, task); err != nil {
		s.log.Warn("jobs: cannot record the task", "job", jobID, "err", err)
		task = nil
	} else {
		s.tasks.add(task.ID, cancelTask)
		defer s.tasks.remove(task.ID)
	}
	status := "failed"
	var runID *int64
	var out taskOutcome
	if jr.Shell == "package" {
		run, ok, err := s.runPackage(ctx, d, jr.CreatedBy, jr.Body, &jobID)
		if err == nil {
			runID = &run.ID
			if ok {
				status = "done"
				s.requestInventory(ctx, d.ID) // the installed programs changed
			}
			result := run.Error
			if result == "" {
				result = "exit code " + strconv.Itoa(*run.ExitCode)
				out = outcome(ok, s.deviceURL(d, "/scripts/"+strconv.FormatInt(run.ID, 10)), "exit code %s", *run.ExitCode)
			} else {
				out = outcome(false, s.deviceURL(d, "/scripts/"+strconv.FormatInt(run.ID, 10)), run.Error)
			}
			_ = s.store.Audit(ctx, jr.CreatedBy, "", "package.install", deviceTarget(d), "job #"+strconv.FormatInt(jr.JobID, 10)+": install "+jr.Name+" on \""+d.Hostname+"\": "+status+" ("+result+")")
		} else {
			out = outcome(false, "", err.Error())
		}
	} else {
		run, err := s.runScript(ctx, d, jr.CreatedBy, jr.Shell, jr.Body, jr.Timeout, &jobID)
		if err == nil {
			runID = &run.ID
			link := s.deviceURL(d, "/scripts/"+strconv.FormatInt(run.ID, 10))
			switch {
			case run.Error != "":
				out = outcome(false, link, run.Error)
			case run.TimedOut:
				out = outcome(false, link, "time limit reached")
			default:
				out = outcome(*run.ExitCode == 0, link, "exit code %s", *run.ExitCode)
			}
			if out.OK {
				status = "done"
			}
			_ = s.store.Audit(ctx, jr.CreatedBy, "", "script.run", deviceTarget(d), "job #"+strconv.FormatInt(jr.JobID, 10)+" ("+jr.Name+"): "+scriptAudit(d, run))
		} else {
			out = outcome(false, "", err.Error())
		}
	}
	if errors.Is(context.Cause(base), errTaskCancelled) {
		status, out = "cancelled", outcome(false, out.Link, "stopped from the console")
	}
	if err := s.store.FinishJobRun(context.Background(), jr.JobID, jr.DeviceID, status, runID); err != nil {
		s.log.Warn("jobs: cannot store a result", "job", jr.JobID, "device", jr.DeviceID, "err", err)
	}
	if task != nil {
		taskStatus := status
		if taskStatus != "done" && taskStatus != "cancelled" {
			taskStatus = "failed"
		}
		_ = s.store.FinishTask(context.Background(), task.ID, taskStatus, out.Result, out.Args, out.Link)
	}
	s.DispatchJobs(context.Background()) // the device's next pending job
}

// ---- library pages

type libraryData struct {
	Scripts   []store.LibScript
	Jobs      []store.ScriptJob
	Schedules []store.ScriptSchedule
}

func (s *Server) handleLibrary(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if !u.CanWrite() {
		s.forbidden(w, r)
		return
	}
	list, err := s.store.LibScripts(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	jobs, err := s.store.Jobs(r.Context(), jobOwner(u), 0, 30)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	ld := &libraryData{Scripts: list, Jobs: jobs}
	if u.IsAdmin() {
		if ld.Schedules, err = s.store.Schedules(r.Context(), 0); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	s.render(w, r, http.StatusOK, "library", &Page{Title: "Script library", Nav: "scripts", Data: ld})
}

// jobOwner limits technicians to their own jobs.
func jobOwner(u *store.User) string {
	if u.IsAdmin() {
		return ""
	}
	return u.Username
}

type libScriptData struct {
	S         *store.LibScript
	Jobs      []store.ScriptJob
	Schedules []store.ScriptSchedule
	Days      []int
	Customers []store.Customer
}

func (s *Server) libScriptFor(w http.ResponseWriter, r *http.Request) *store.LibScript {
	if !userFrom(r).CanWrite() {
		s.forbidden(w, r)
		return nil
	}
	id, ok := pathID(r, "sid")
	if !ok {
		s.notFound(w, r)
		return nil
	}
	x, err := s.store.LibScript(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, r)
		return nil
	}
	if err != nil {
		s.serverError(w, r, err)
		return nil
	}
	return x
}

func (s *Server) handleLibScript(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if r.PathValue("sid") == "" { // /scripts/new
		if !u.IsAdmin() {
			s.forbidden(w, r)
			return
		}
		s.render(w, r, http.StatusOK, "libscript", &Page{Title: "New script", Nav: "scripts", Data: &libScriptData{S: &store.LibScript{Shell: "powershell", Timeout: 300}}})
		return
	}
	x := s.libScriptFor(w, r)
	if x == nil {
		return
	}
	d := &libScriptData{S: x, Days: weekdays}
	var err error
	if d.Jobs, err = s.store.Jobs(r.Context(), jobOwner(u), x.ID, 20); err != nil {
		s.serverError(w, r, err)
		return
	}
	if u.IsAdmin() {
		if d.Schedules, err = s.store.Schedules(r.Context(), x.ID); err != nil {
			s.serverError(w, r, err)
			return
		}
		if d.Customers, err = s.store.Customers(r.Context(), u); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	s.render(w, r, http.StatusOK, "libscript", &Page{Title: x.Name, Nav: "scripts", Data: d})
}

func (s *Server) handleLibScriptSave(w http.ResponseWriter, r *http.Request) {
	x := &store.LibScript{Name: strings.TrimSpace(r.FormValue("name")), Description: strings.TrimSpace(r.FormValue("description")),
		Shell: r.FormValue("shell"), Body: strings.ReplaceAll(r.FormValue("script"), "\r\n", "\n"), UpdatedBy: s.issuer(r)}
	x.Timeout, _ = strconv.Atoi(r.FormValue("timeout"))
	back := "/scripts/new"
	if id, ok := pathID(r, "sid"); ok {
		x.ID = id
		back = "/scripts/" + strconv.FormatInt(id, 10)
	}
	if x.Name == "" || len(x.Name) > 120 || len(x.Description) > 1000 {
		s.redirect(w, r, back, "Enter a name (up to 120 characters).")
		return
	}
	if msg := checkScript(x.Shell, x.Body, x.Timeout); msg != "" {
		s.redirect(w, r, back, msg)
		return
	}
	err := s.store.SaveLibScript(r.Context(), x)
	if errors.Is(err, store.ErrConflict) {
		s.redirect(w, r, back, "A script with this name already exists.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "library.save", "script:"+strconv.FormatInt(x.ID, 10), "saved library script %q (%s, %d s)\n--- script ---\n%s", x.Name, x.Shell, x.Timeout, clip(x.Body, auditScript))
	s.redirect(w, r, "/scripts/"+strconv.FormatInt(x.ID, 10), "Saved.")
}

func (s *Server) handleLibScriptDelete(w http.ResponseWriter, r *http.Request) {
	x := s.libScriptFor(w, r)
	if x == nil {
		return
	}
	if err := s.store.DeleteLibScript(r.Context(), x.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "library.delete", "script:"+strconv.FormatInt(x.ID, 10), "deleted library script %q and its schedules", x.Name)
	s.redirect(w, r, "/scripts", translate(s.lang(r, userFrom(r)), "Script %s deleted.", x.Name))
}

// ---- running a library script on many devices

type targetData struct {
	S         *store.LibScript
	P         *store.SoftwarePackage
	Customers []store.Customer
	Sites     []store.Site
	Devices   []*store.Device
	Online    map[int64]bool
}

func (s *Server) handleJobNew(w http.ResponseWriter, r *http.Request) {
	x := s.libScriptFor(w, r)
	if x == nil {
		return
	}
	td, err := s.targets(r, false)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	td.S = x
	s.render(w, r, http.StatusOK, "jobnew", &Page{Title: x.Name, Nav: "scripts", Data: td})
}

func parseTarget(r *http.Request) store.ScriptTarget {
	_ = r.ParseForm()
	ids := func(name string) []int64 {
		var out []int64
		for _, v := range r.Form[name] {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
				out = append(out, n)
			}
		}
		return out
	}
	return store.ScriptTarget{All: r.FormValue("all") == "1", Customers: ids("customer"), Sites: ids("site"), Devices: ids("device")}
}

func (s *Server) handleJobCreate(w http.ResponseWriter, r *http.Request) {
	x := s.libScriptFor(w, r)
	if x == nil {
		return
	}
	u := userFrom(r)
	t := parseTarget(r)
	if t.All && !u.IsAdmin() && !u.AllCustomers {
		t.All = false // never more than the user may see; ResolveTarget filters too
	}
	back := "/scripts/" + strconv.FormatInt(x.ID, 10) + "/run"
	if t.Empty() {
		s.redirect(w, r, back, "Choose the devices.")
		return
	}
	ids, err := s.store.ResolveTarget(r.Context(), u, t)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(ids) == 0 {
		s.redirect(w, r, back, "Choose the devices.")
		return
	}
	sid := x.ID
	j := &store.ScriptJob{ScriptID: &sid, Name: x.Name, Shell: x.Shell, Body: x.Body, Timeout: x.Timeout, CreatedBy: u.Username, ExpiresAt: s.now().Add(jobLifetime)}
	if err := s.store.CreateJob(r.Context(), j, ids); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "job.create", "job:"+strconv.FormatInt(j.ID, 10), "run library script %q on %d devices", x.Name, len(ids))
	go s.DispatchJobs(context.Background()) // #nosec G118 -- the job runs after the page has answered
	s.redirect(w, r, "/jobs/"+strconv.FormatInt(j.ID, 10), "")
}

type jobData struct {
	J       *store.ScriptJob
	Devices []store.JobDevice
	Active  bool
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if !u.CanWrite() {
		s.forbidden(w, r)
		return
	}
	id, ok := pathID(r, "jid")
	if !ok {
		s.notFound(w, r)
		return
	}
	j, err := s.store.Job(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) || err == nil && !u.IsAdmin() && j.CreatedBy != u.Username {
		s.notFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	devs, err := s.store.JobDevices(r.Context(), id)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	sort.SliceStable(devs, func(a, b int) bool { return statusOrder(devs[a].Status) < statusOrder(devs[b].Status) })
	s.render(w, r, http.StatusOK, "job", &Page{Title: j.Name, Nav: "scripts", Data: &jobData{J: j, Devices: devs, Active: j.Pending+j.Running > 0}})
}

func statusOrder(st string) int {
	return map[string]int{"failed": 0, "running": 1, "pending": 2, "expired": 3, "cancelled": 3, "done": 4}[st]
}

// ---- schedules

func (s *Server) handleScheduleAdd(w http.ResponseWriter, r *http.Request) {
	x := s.libScriptFor(w, r)
	if x == nil {
		return
	}
	back := "/scripts/" + strconv.FormatInt(x.ID, 10)
	t := parseTarget(r)
	sc := &store.ScriptSchedule{ScriptID: x.ID, Target: t, CreatedBy: s.issuer(r)}
	for _, v := range r.Form["day"] {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 6 {
			sc.Days = append(sc.Days, n)
		}
	}
	tm, err := time.Parse("15:04", r.FormValue("time"))
	if t.Empty() || len(sc.Days) == 0 || err != nil {
		s.redirect(w, r, back, "Choose the devices, at least one day and the time.")
		return
	}
	sc.Minute = tm.Hour()*60 + tm.Minute()
	if err := s.store.AddSchedule(r.Context(), sc); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "schedule.add", "script:"+strconv.FormatInt(x.ID, 10), "scheduled library script %q at %s on days %v", x.Name, r.FormValue("time"), sc.Days)
	s.redirect(w, r, back, "Saved.")
}

func (s *Server) handleScheduleChange(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	var err error
	switch r.FormValue("action") {
	case "enable":
		err = s.store.SetScheduleEnabled(r.Context(), id, true)
	case "disable":
		err = s.store.SetScheduleEnabled(r.Context(), id, false)
	case "delete":
		err = s.store.DeleteSchedule(r.Context(), id)
	default:
		s.redirect(w, r, "/scripts", "Unknown action.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "schedule."+r.FormValue("action"), "schedule:"+strconv.FormatInt(id, 10), "%s script schedule #%d", r.FormValue("action"), id)
	back := "/scripts"
	if ref, err := urlPath(r.Referer()); err == nil && strings.HasPrefix(ref, "/scripts") {
		back = safeNext(ref)
	}
	s.redirect(w, r, back, "Saved.")
}

// RunSchedules creates the jobs of schedules that are due (monitor loop).
func (s *Server) RunSchedules(ctx context.Context) {
	list, err := s.store.Schedules(ctx, 0)
	if err != nil {
		s.log.Warn("schedules: cannot load", "err", err)
		return
	}
	now := s.now().Local()
	minute := now.Hour()*60 + now.Minute()
	slot := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), 0, 0, now.Location())
	for _, sc := range list {
		if !sc.Enabled || sc.Minute > minute || minute-sc.Minute > 10 || !containsInt(sc.Days, int(now.Weekday())) {
			continue
		}
		due := slot.Add(-time.Duration(minute-sc.Minute) * time.Minute)
		if sc.LastFired != nil && !sc.LastFired.Before(due) {
			continue
		}
		if ok, err := s.store.MarkScheduleFired(ctx, sc.ID, due); err != nil || !ok {
			continue
		}
		x, err := s.store.LibScript(ctx, sc.ScriptID)
		if err != nil {
			continue
		}
		ids, err := s.store.ResolveTarget(ctx, nil, sc.Target)
		if err != nil || len(ids) == 0 {
			continue
		}
		sid, schedID := x.ID, sc.ID
		j := &store.ScriptJob{ScriptID: &sid, ScheduleID: &schedID, Name: x.Name, Shell: x.Shell, Body: x.Body, Timeout: x.Timeout,
			CreatedBy: sc.CreatedBy, ExpiresAt: s.now().Add(jobLifetime)}
		if err := s.store.CreateJob(ctx, j, ids); err != nil {
			s.log.Warn("schedules: cannot create a job", "schedule", sc.ID, "err", err)
			continue
		}
		_ = s.store.Audit(ctx, "system", "", "job.create", "job:"+strconv.FormatInt(j.ID, 10), "schedule #"+strconv.FormatInt(sc.ID, 10)+" runs library script \""+x.Name+"\" on "+strconv.Itoa(len(ids))+" devices")
	}
	s.DispatchJobs(ctx)
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
