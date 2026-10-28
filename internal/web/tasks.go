package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

// Device activity: every action of the console on an agent is a task. A
// task waits until its device is online (up to taskLifetime), the tasks of a
// device run one after the other, a running task can be cancelled (the
// agent stops what it runs for it), and finished tasks stay as history.
// Job runs (library scripts and packages on many devices) show up as tasks
// of their devices too. Titles and results are translation keys with
// arguments, so the activity reads in each user's language.

const (
	taskLifetime = 24 * time.Hour
	// taskWait is how long a page waits for a new task before it shows the
	// device's activity instead (quick tasks show their result at once).
	taskWait = 20 * time.Second
)

var errTaskCancelled = errors.New("cancelled")

type taskRunner struct {
	mu      sync.Mutex
	running map[int64]context.CancelCauseFunc
}

func (t *taskRunner) add(id int64, cancel context.CancelCauseFunc) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running == nil {
		t.running = map[int64]context.CancelCauseFunc{}
	}
	t.running[id] = cancel
}

func (t *taskRunner) remove(id int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.running, id)
}

func (t *taskRunner) cancel(id int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c := t.running[id]; c != nil {
		c(errTaskCancelled)
		return true
	}
	return false
}

// taskOutcome is how a task ended: a translation key and its arguments.
type taskOutcome struct {
	OK     bool
	Result string
	Args   []string
	Link   string // where the details are
}

func outcome(ok bool, link, result string, args ...any) taskOutcome {
	o := taskOutcome{OK: ok, Result: result, Link: link}
	for _, a := range args {
		o.Args = append(o.Args, fmt.Sprint(a))
	}
	return o
}

// taskKind runs one kind of task on a connected device.
type taskKind func(s *Server, ctx context.Context, d *store.Device, t *store.DeviceTask) (taskOutcome, error)

var taskKinds = map[string]taskKind{}

// queueTask adds a task for a device and starts it if the device is online.
// title is a translation key, titleArgs fill its %s.
func (s *Server) queueTask(ctx context.Context, d *store.Device, by, kind, title string, titleArgs []string, args any) (*store.DeviceTask, error) {
	if taskKinds[kind] == nil {
		return nil, fmt.Errorf("unknown task %q", kind)
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	t := &store.DeviceTask{DeviceID: d.ID, Kind: kind, Title: title, TitleArgs: titleArgs, Args: raw, CreatedBy: by, ExpiresAt: s.now().Add(taskLifetime)}
	if err := s.store.AddTask(ctx, t); err != nil {
		return nil, err
	}
	go s.dispatchTasks(context.Background(), []int64{d.ID}) // #nosec G118 -- the task outlives the request that queued it
	return t, nil
}

// DispatchTasks starts the next queued task of each connected device that
// runs none. It is called when a task is queued, when an agent connects,
// when a task ends and every minute.
func (s *Server) DispatchTasks(ctx context.Context) {
	if err := s.store.ExpireTasks(ctx, false); err != nil {
		s.log.Warn("tasks: cannot expire", "err", err)
	}
	s.dispatchTasks(ctx, s.hub.connectedIDs())
}

// dispatchTasks starts the next queued task of the given devices.
func (s *Server) dispatchTasks(ctx context.Context, ids []int64) {
	ids = s.onlyConnected(ids)
	if len(ids) == 0 {
		return
	}
	list, err := s.store.ClaimTasks(ctx, ids)
	if err != nil {
		s.log.Warn("tasks: cannot claim", "err", err)
		return
	}
	for i := range list {
		go s.runTask(&list[i]) // #nosec G118 -- a task outlives the call that started it; own timeout
	}
}

func (s *Server) runTask(t *store.DeviceTask) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	s.tasks.add(t.ID, cancel)
	defer s.tasks.remove(t.ID)
	out, err := s.taskBody(ctx, t)
	status := "done"
	switch {
	case errors.Is(context.Cause(ctx), errTaskCancelled):
		status, out.Result, out.Args = "cancelled", "stopped from the console", nil
	case err != nil:
		status, out.Result, out.Args = "failed", clip(err.Error(), 2000), nil
	case !out.OK:
		status = "failed"
	}
	if err := s.store.FinishTask(context.Background(), t.ID, status, out.Result, out.Args, out.Link); err != nil {
		s.log.Warn("tasks: cannot store a result", "task", t.ID, "err", err)
	}
	s.dispatchTasks(context.Background(), []int64{t.DeviceID}) // the device's next task
}

func (s *Server) taskBody(ctx context.Context, t *store.DeviceTask) (taskOutcome, error) {
	d, err := s.store.Device(ctx, t.DeviceID)
	if err != nil {
		return taskOutcome{}, err
	}
	return taskKinds[t.Kind](s, ctx, d, t)
}

// awaitTask waits a little for a task to end and returns its state.
func (s *Server) awaitTask(ctx context.Context, id int64, max time.Duration) *store.DeviceTask {
	deadline := time.Now().Add(max)
	for {
		t, err := s.store.Task(ctx, id)
		if err != nil || !t.Active() || time.Now().After(deadline) || ctx.Err() != nil {
			return t
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func taskText(lang, key string, args []string) string {
	a := make([]any, len(args))
	for i, x := range args {
		a[i] = x
	}
	return translate(lang, key, a...)
}

// startTask queues a task from a page and answers: with the task's own page
// when it ended quickly, otherwise with the device's activity.
func (s *Server) startTask(w http.ResponseWriter, r *http.Request, d *store.Device, kind, title string, titleArgs []string, args any) {
	t, err := s.queueTask(r.Context(), d, s.issuer(r), kind, title, titleArgs, args)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	activity := s.deviceURL(d, "/activity")
	wait := taskWait
	if s.TaskWait > 0 {
		wait = s.TaskWait
	}
	t = s.awaitTask(r.Context(), t.ID, wait)
	lang := s.lang(r, userFrom(r))
	if t == nil {
		s.redirect(w, r, activity, "")
		return
	}
	name := taskText(lang, t.Title, t.TitleArgs)
	result := name + ": " + taskText(lang, t.Result, t.ResultArgs)
	switch {
	case t.Status == "queued" && !s.Connected(d.ID):
		s.redirect(w, r, activity, translate(lang, "%s is offline; the task waits until it connects (up to 24 hours).", d.Hostname))
	case t.Active():
		s.redirect(w, r, activity, translate(lang, "%s is still running; this page shows when it is done.", name))
	case t.Link != "":
		s.redirect(w, r, t.Link, result)
	default:
		s.redirect(w, r, activity, result)
	}
}

// ---- the activity page

type activityData struct {
	D       *store.Device
	Tasks   []store.DeviceTask
	Jobs    []store.PendingJobRun
	Running int
	Queued  int
}

func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	tasks, err := s.store.DeviceTasks(r.Context(), d.ID, 50)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	jobs, err := s.store.PendingJobRuns(r.Context(), d.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	ad := &activityData{D: d, Tasks: tasks, Jobs: jobs, Queued: len(jobs)}
	for _, t := range tasks {
		switch t.Status {
		case "running":
			ad.Running++
		case "queued":
			ad.Queued++
		}
	}
	s.render(w, r, http.StatusOK, "activity", &Page{Title: d.Hostname, Nav: "devices", Data: ad})
}

func (s *Server) handleTaskCancel(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	back := s.deviceURL(d, "/activity")
	id, ok := pathID(r, "tid")
	t, err := s.store.Task(r.Context(), id)
	if !ok || err != nil || t.DeviceID != d.ID {
		s.redirect(w, r, back, "Unknown action.")
		return
	}
	lang := s.lang(r, userFrom(r))
	name := taskText(lang, t.Title, t.TitleArgs)
	if done, err := s.store.CancelQueuedTask(r.Context(), t.ID, s.issuer(r)); err != nil {
		s.serverError(w, r, err)
		return
	} else if done {
		s.audit(r, "task.cancel", deviceTarget(d), "cancelled waiting task #%d (%s) on %q", t.ID, taskText("en", t.Title, t.TitleArgs), d.Hostname)
		s.redirect(w, r, back, translate(lang, "%s was cancelled.", name))
		return
	}
	if !s.tasks.cancel(t.ID) {
		s.redirect(w, r, back, translate(lang, "%s has already ended.", name))
		return
	}
	s.audit(r, "task.cancel", deviceTarget(d), "stopped running task #%d (%s) on %q", t.ID, taskText("en", t.Title, t.TitleArgs), d.Hostname)
	s.redirect(w, r, back, translate(lang, "%s is being stopped.", name))
}

func (s *Server) handleJobRunCancel(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	back := s.deviceURL(d, "/activity")
	jid, ok := pathID(r, "jid")
	if !ok {
		s.redirect(w, r, back, "Unknown action.")
		return
	}
	done, err := s.store.CancelJobRun(r.Context(), jid, d.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !done {
		s.redirect(w, r, back, "The job has already started or ended on this device.")
		return
	}
	s.audit(r, "task.cancel", deviceTarget(d), "cancelled job #%d on %q", jid, d.Hostname)
	s.redirect(w, r, back, "Cancelled.")
}

// ---- kinds of tasks

func init() {
	taskKinds["script"] = taskScript
	taskKinds["winget"] = taskWinget
	taskKinds["choco"] = taskChoco
	taskKinds["uninstall"] = taskUninstall
	taskKinds["patch.scan"] = taskPatchScan
	taskKinds["patch.install"] = taskPatchInstall
	taskKinds["agent.update"] = taskAgentUpdate
	taskKinds["power"] = taskPower
}

func taskArgs(t *store.DeviceTask, v any) error {
	if err := json.Unmarshal(t.Args, v); err != nil {
		return errors.New("bad task")
	}
	return nil
}

func (s *Server) taskAudit(ctx context.Context, t *store.DeviceTask, d *store.Device, action, format string, args ...any) {
	_ = s.store.Audit(context.WithoutCancel(ctx), t.CreatedBy, "", action, deviceTarget(d), fmt.Sprintf(format, args...))
}

// scriptTask is a script typed on the device's Scripts tab.
type scriptTask struct {
	Shell   string `json:"shell"`
	Script  string `json:"script"`
	Timeout int    `json:"timeout"`
}

func taskScript(s *Server, ctx context.Context, d *store.Device, t *store.DeviceTask) (taskOutcome, error) {
	var a scriptTask
	if err := taskArgs(t, &a); err != nil {
		return taskOutcome{}, err
	}
	run, err := s.runScript(ctx, d, t.CreatedBy, a.Shell, a.Script, a.Timeout, nil)
	if err != nil {
		return taskOutcome{}, err
	}
	s.taskAudit(ctx, t, d, "script.run", "%s", scriptAudit(d, run))
	link := s.deviceURL(d, "/scripts/"+strconv.FormatInt(run.ID, 10))
	switch {
	case run.Error != "":
		return outcome(false, link, run.Error), nil
	case run.TimedOut:
		return outcome(false, link, "time limit reached"), nil
	}
	return outcome(*run.ExitCode == 0, link, "exit code %s", *run.ExitCode), nil
}

// wingetTask installs, updates or uninstalls with winget.
type wingetTask struct {
	proto.Winget
	Back string `json:"back"`
}

func taskWinget(s *Server, ctx context.Context, d *store.Device, t *store.DeviceTask) (taskOutcome, error) {
	var a wingetTask
	if err := taskArgs(t, &a); err != nil {
		return taskOutcome{}, err
	}
	var res proto.WingetResult
	err := s.call(ctx, d.ID, t.CreatedBy, proto.KindWinget, a.Winget, &res, 27*time.Minute)
	what := a.ID
	if a.ID == proto.WingetAll {
		what = "all packages"
	}
	if err != nil {
		s.taskAudit(ctx, t, d, "software."+a.Action, "winget %s %s on %q failed: %v", a.Action, what, d.Hostname, err)
		return taskOutcome{}, err
	}
	code := fmt.Sprintf("0x%X", uint32(res.ExitCode)) // #nosec G115 -- exit codes are 32-bit
	s.taskAudit(ctx, t, d, "software."+a.Action, "winget %s %s on %q: exit code %s\n%s", a.Action, what, d.Hostname, code, clip(res.Output, auditOutput))
	if res.ExitCode != 0 {
		return outcome(false, a.Back, "winget ended with code %s; the audit log has its output.", code), nil
	}
	s.requestInventory(ctx, d.ID) // the installed programs changed
	return outcome(true, a.Back, "done"), nil
}

// chocoTask installs or updates with Chocolatey.
type chocoTask struct {
	proto.Choco
	Back string `json:"back"`
}

func taskChoco(s *Server, ctx context.Context, d *store.Device, t *store.DeviceTask) (taskOutcome, error) {
	var a chocoTask
	if err := taskArgs(t, &a); err != nil {
		return taskOutcome{}, err
	}
	var res proto.WingetResult
	err := s.call(ctx, d.ID, t.CreatedBy, proto.KindChoco, a.Choco, &res, 27*time.Minute)
	what := a.ID
	if a.ID == proto.WingetAll {
		what = "all packages"
	}
	if err != nil {
		s.taskAudit(ctx, t, d, "software."+a.Action, "choco %s %s on %q failed: %v", a.Action, what, d.Hostname, err)
		return taskOutcome{}, err
	}
	s.taskAudit(ctx, t, d, "software."+a.Action, "choco %s %s on %q: exit code %d\n%s", a.Action, what, d.Hostname, res.ExitCode, clip(res.Output, auditOutput))
	if res.ExitCode != 0 {
		return outcome(false, a.Back, "Chocolatey ended with code %s; the audit log has its output.", res.ExitCode), nil
	}
	s.requestInventory(ctx, d.ID)
	return outcome(true, a.Back, "done"), nil
}

// uninstallTask removes an installed program silently.
type uninstallTask struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	Back string `json:"back"`
}

func taskUninstall(s *Server, ctx context.Context, d *store.Device, t *store.DeviceTask) (taskOutcome, error) {
	var a uninstallTask
	if err := taskArgs(t, &a); err != nil {
		return taskOutcome{}, err
	}
	var res proto.UninstallResult
	err := s.call(ctx, d.ID, t.CreatedBy, proto.KindUninstall, proto.Uninstall{Key: a.Key}, &res, 27*time.Minute)
	if err != nil {
		s.taskAudit(ctx, t, d, "software.uninstall", "uninstall %s (%s) on %q failed: %v", clip(a.Name, 200), a.Key, d.Hostname, err)
		return taskOutcome{}, err
	}
	s.taskAudit(ctx, t, d, "software.uninstall", "uninstalled %s (%s, %s) on %q: exit code %d", res.Name, a.Key, res.Method, d.Hostname, res.ExitCode)
	s.requestInventory(ctx, d.ID)
	return outcome(true, a.Back, "done"), nil
}

// patchWait waits until the device's update report shows the end of a scan
// or an installation.
func (s *Server) patchWait(ctx context.Context, d *store.Device, ended func(r *proto.PatchReport) bool, limit time.Duration) (*proto.PatchReport, error) {
	deadline := time.Now().Add(limit)
	for {
		rep, _, err := s.store.PatchReport(ctx, d.ID)
		if err == nil && rep != nil && ended(rep) {
			return rep, nil
		}
		if time.Now().After(deadline) {
			return nil, errors.New("the device did not report the end in time")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func taskPatchScan(s *Server, ctx context.Context, d *store.Device, t *store.DeviceTask) (taskOutcome, error) {
	before := time.Time{}
	if rep, _, err := s.store.PatchReport(ctx, d.ID); err == nil && rep != nil {
		before = rep.ScannedAt
	}
	if err := s.call(ctx, d.ID, t.CreatedBy, proto.KindPatchScan, nil, nil, actionTimeout); err != nil {
		return taskOutcome{}, err
	}
	s.taskAudit(ctx, t, d, "patch.scan", "search for Windows updates on %q", d.Hostname)
	link := s.deviceURL(d, "/updates")
	rep, err := s.patchWait(ctx, d, func(r *proto.PatchReport) bool {
		return r.State == proto.PatchIdle && (r.ScannedAt.After(before) || r.ScanError != "")
	}, 35*time.Minute)
	if errors.Is(context.Cause(ctx), errTaskCancelled) {
		s.cancelPatchJob(d)
	}
	if err != nil {
		return taskOutcome{Link: link}, err
	}
	if rep.ScanError != "" && !rep.ScannedAt.After(before) {
		return outcome(false, link, rep.ScanError), nil
	}
	return outcome(true, link, "%s updates missing", len(rep.Updates)), nil
}

// patchInstallTask installs Windows updates (the agent installs in the
// background and reports the end with its update state).
type patchInstallTask struct {
	proto.PatchInstall
	Titles []string `json:"titles"`
}

func taskPatchInstall(s *Server, ctx context.Context, d *store.Device, t *store.DeviceTask) (taskOutcome, error) {
	var a patchInstallTask
	if err := taskArgs(t, &a); err != nil {
		return taskOutcome{}, err
	}
	var before time.Time
	if rep, _, err := s.store.PatchReport(ctx, d.ID); err == nil && rep != nil && rep.Install != nil {
		before = rep.Install.Started
	}
	if err := s.call(ctx, d.ID, t.CreatedBy, proto.KindPatchInstall, a.PatchInstall, nil, actionTimeout); err != nil {
		return taskOutcome{}, err
	}
	link := s.deviceURL(d, "/updates")
	s.taskAudit(ctx, t, d, "patch.install", "install %d Windows updates on %q (restart if needed: %v): %s", len(a.IDs), d.Hostname, a.Reboot, strings.Join(a.Titles, "; "))
	rep, err := s.patchWait(ctx, d, func(r *proto.PatchReport) bool {
		return r.Install != nil && r.Install.Started.After(before) && !r.Install.Finished.IsZero()
	}, 4*time.Hour+10*time.Minute)
	if errors.Is(context.Cause(ctx), errTaskCancelled) {
		s.cancelPatchJob(d)
		return taskOutcome{Link: link}, nil
	}
	if err != nil {
		return taskOutcome{Link: link}, err
	}
	run := rep.Install
	if run.Error != "" {
		return outcome(false, link, run.Error), nil
	}
	if len(run.Results) == 0 {
		return outcome(true, link, "nothing to install (already installed or no longer offered)"), nil
	}
	ok, failed := 0, 0
	for _, x := range run.Results {
		if x.Result == 2 || x.Result == 3 {
			ok++
		} else {
			failed++
		}
	}
	if run.RebootRequired {
		return outcome(failed == 0, link, "%s installed, %s failed; a restart completes the installation", ok, failed), nil
	}
	return outcome(failed == 0, link, "%s installed, %s failed", ok, failed), nil
}

// cancelPatchJob asks the agent to stop its Windows Update scan or
// installation.
func (s *Server) cancelPatchJob(d *store.Device) {
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()
	if err := s.call(ctx, d.ID, "system", proto.KindPatchCancel, nil, nil, actionTimeout); err != nil {
		s.log.Warn("cannot stop the Windows Update job", "device", d.ID, "err", err)
	}
}

func taskAgentUpdate(s *Server, ctx context.Context, d *store.Device, t *store.DeviceTask) (taskOutcome, error) {
	pkg := s.packageFor(s.devicePlatform(ctx, d))
	if pkg == nil {
		return taskOutcome{}, errors.New("there is no agent installer with a known version for this device on the server")
	}
	if err := s.updateDevice(ctx, d, t.CreatedBy); err != nil {
		s.taskAudit(ctx, t, d, "agent.update", "update of %q failed: %v", d.Hostname, err)
		return taskOutcome{}, err
	}
	s.taskAudit(ctx, t, d, "agent.update", "update of %q from %s to %s started", d.Hostname, d.AgentVersion, pkg.Version)
	// Done when the agent reconnects with the new version.
	deadline := time.Now().Add(15 * time.Minute)
	for time.Now().Before(deadline) {
		if x, err := s.store.Device(ctx, d.ID); err == nil && x.AgentVersion == pkg.Version && s.Connected(d.ID) {
			return outcome(true, s.deviceURL(d, ""), "agent %s is running", pkg.Version), nil
		}
		select {
		case <-ctx.Done():
			return taskOutcome{}, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return taskOutcome{}, errors.New("the agent did not come back with the new version in 15 minutes")
}

func taskPower(s *Server, ctx context.Context, d *store.Device, t *store.DeviceTask) (taskOutcome, error) {
	var a proto.Power
	if err := taskArgs(t, &a); err != nil {
		return taskOutcome{}, err
	}
	if err := s.call(ctx, d.ID, t.CreatedBy, proto.KindPower, a, nil, actionTimeout); err != nil {
		s.taskAudit(ctx, t, d, "power."+a.Action, "%s of %q failed: %v", a.Action, d.Hostname, err)
		return taskOutcome{}, err
	}
	s.taskAudit(ctx, t, d, "power."+a.Action, "%s of %q (in %d s)", a.Action, d.Hostname, a.Delay)
	switch a.Action {
	case "restart":
		return outcome(true, "", "The computer restarts in %s seconds.", a.Delay), nil
	case "shutdown":
		return outcome(true, "", "The computer shuts down in %s seconds.", a.Delay), nil
	}
	return outcome(true, "", "The scheduled restart or shutdown was cancelled."), nil
}
