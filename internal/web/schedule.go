package web

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

// Program updates, update rings, restarts with a deadline and maintenance
// windows: the parts of a policy that decide when devices change.

// AppUpdatePolicy updates the installed programs that winget or Chocolatey
// know, on set days or in the maintenance window.
type AppUpdatePolicy struct {
	Winget    bool     `json:"winget"`
	Choco     bool     `json:"choco"`
	Exclude   []string `json:"exclude,omitempty"` // package IDs or parts of names
	Days      []int    `json:"days"`
	Hour      int      `json:"hour"`
	InWindow  bool     `json:"in_window,omitempty"`  // in the maintenance window instead of days and hour
	DelayDays int      `json:"delay_days,omitempty"` // update ring: a new version waits this long
}

// MaintenancePolicy sets when devices may be busy: installations "in the
// maintenance window", forced restarts, and no new alerts while quiet.
type MaintenancePolicy struct {
	Windows []MaintWindow `json:"windows"`
	Quiet   bool          `json:"quiet,omitempty"` // no new alerts during a window
}

// MaintWindow is a weekly time span, server time.
type MaintWindow struct {
	Days  []int  `json:"days"`  // weekdays it starts on
	Start int    `json:"start"` // minute of the day
	Hours int    `json:"hours"` // 1–24
	Key   string `json:"-"`     // the row of the form
}

// Time is the start as HH:MM.
func (w MaintWindow) Time() string { return fmt.Sprintf("%02d:%02d", w.Start/60, w.Start%60) }

// active reports whether now is inside one of the windows.
func (m *MaintenancePolicy) active(now time.Time) bool {
	if m == nil {
		return false
	}
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	for _, w := range m.Windows {
		// A window can start today or on an earlier day and still run.
		for back := 0; back <= 1; back++ {
			d := day.AddDate(0, 0, -back)
			if !containsInt(w.Days, int(d.Weekday())) {
				continue
			}
			start := d.Add(time.Duration(w.Start) * time.Minute)
			if !now.Before(start) && now.Before(start.Add(time.Duration(w.Hours)*time.Hour)) {
				return true
			}
		}
	}
	return false
}

func (m *MaintenancePolicy) validate() error {
	if len(m.Windows) > 14 {
		return errors.New("at most 14 maintenance windows")
	}
	for _, w := range m.Windows {
		if len(w.Days) == 0 || w.Start < 0 || w.Start >= 1440 || w.Hours < 1 || w.Hours > 24 {
			return errors.New("each maintenance window needs at least one day, its start and 1–24 hours")
		}
	}
	return nil
}

func (a *AppUpdatePolicy) validate() error {
	if a.Hour < 0 || a.Hour > 23 || len(a.Days) > 7 || len(a.Exclude) > 100 || a.DelayDays < 0 || a.DelayDays > 60 {
		return errors.New("program updates: choose the days, an hour 0–23 and a delay of 0–60 days")
	}
	if !a.InWindow && len(a.Days) == 0 && (a.Winget || a.Choco) {
		return errors.New("program updates: choose at least one day")
	}
	return nil
}

// scheduleDue reports whether an installation set for days and hour, or for
// the maintenance window, is due now.
func scheduleDue(days []int, hour int, inWindow bool, mw *MaintenancePolicy, now time.Time) bool {
	if inWindow {
		return mw.active(now)
	}
	return containsInt(days, int(now.Weekday())) && now.Hour() == hour
}

func (pr *policyResolver) appUpdates(deviceID int64) (*AppUpdatePolicy, *policyLevel) {
	if l := pr.part(deviceID, func(p *PolicySettings) bool { return p.AppUpdates != nil }); l != nil {
		return l.Settings.AppUpdates, l
	}
	return nil, nil
}

func (pr *policyResolver) maintenance(deviceID int64) (*MaintenancePolicy, *policyLevel) {
	if l := pr.part(deviceID, func(p *PolicySettings) bool { return p.Maintenance != nil }); l != nil {
		return l.Settings.Maintenance, l
	}
	return nil, nil
}

func isWindowsOS(os string) bool { return os == "" || strings.Contains(os, "Windows") }

// ---- update rings

// waits reports whether a new item first seen at first still waits for the
// ring's delay.
func ringWaits(first time.Time, delayDays int, now time.Time) bool {
	return delayDays > 0 && !first.IsZero() && now.Sub(first) < time.Duration(delayDays)*24*time.Hour
}

// windowsUpdatesSeen records the updates of a report and returns when each
// was first seen.
func (s *Server) windowsUpdatesSeen(ctx context.Context, r *proto.PatchReport) map[string]time.Time {
	items := make([]store.Seen, 0, len(r.Updates))
	for _, u := range r.Updates {
		items = append(items, store.Seen{ID: u.ID})
	}
	seen, err := s.store.FirstSeen(ctx, "wu", items)
	if err != nil {
		s.log.Warn("update rings: cannot record updates", "err", err)
	}
	return seen
}

// ---- program updates

// RunAppUpdates starts the program updates of policies that are due (monitor
// loop, every minute), once a day per device.
func (s *Server) RunAppUpdates(ctx context.Context) {
	pr, err := s.cachedPolicies(ctx)
	if err != nil {
		return
	}
	now := s.now().Local()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	for id, sc := range pr.scopes {
		a, l := pr.appUpdates(id)
		if a == nil || (!a.Winget && !a.Choco) || !isWindowsOS(sc.OS) {
			continue
		}
		mw, _ := pr.maintenance(id)
		if !scheduleDue(a.Days, a.Hour, a.InWindow, mw, now) {
			continue
		}
		if ok, err := s.store.MarkOnce(ctx, "apps:"+strconv.FormatInt(id, 10), today); err != nil || !ok {
			continue
		}
		d := &store.Device{ID: id, Hostname: sc.Hostname}
		args := appsUpdateTask{Winget: a.Winget, Choco: a.Choco, Exclude: a.Exclude, DelayDays: a.DelayDays}
		if _, err := s.queueTask(ctx, d, "policy "+l.Policy.Name, "apps.update", "Update programs (automatic)", nil, args); err != nil {
			s.log.Warn("program updates", "device", id, "err", err)
		}
	}
}

// appsUpdateTask updates the programs with newer versions.
type appsUpdateTask struct {
	Winget    bool     `json:"winget"`
	Choco     bool     `json:"choco"`
	Exclude   []string `json:"exclude,omitempty"`
	DelayDays int      `json:"delay_days,omitempty"`
}

// excluded reports whether a package is on the policy's exclude list.
func excluded(list []string, p proto.WingetPackage) bool {
	for _, x := range list {
		x = strings.ToLower(strings.TrimSpace(x))
		if x != "" && (strings.EqualFold(p.ID, x) || strings.Contains(strings.ToLower(p.Name), x)) {
			return true
		}
	}
	return false
}

func taskAppsUpdate(s *Server, ctx context.Context, d *store.Device, t *store.DeviceTask) (taskOutcome, error) {
	var a appsUpdateTask
	if err := taskArgs(t, &a); err != nil {
		return taskOutcome{}, err
	}
	var updated, failed, skipped, waiting int
	var done []string
	source := func(name, kind string, list, upgrade func(id string) any) error {
		var res proto.WingetResult
		if err := s.call(ctx, d.ID, t.CreatedBy, kind, list(""), &res, 10*time.Minute); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		items := make([]store.Seen, 0, len(res.Packages))
		for _, p := range res.Packages {
			items = append(items, store.Seen{ID: p.ID, Version: p.Available})
		}
		seen, err := s.store.FirstSeen(ctx, name, items)
		if err != nil {
			return err
		}
		for _, p := range res.Packages {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if excluded(a.Exclude, p) {
				continue
			}
			if unknownVersion(p.Version) {
				skipped++ // winget would offer it every day again
				continue
			}
			if ringWaits(seen[p.ID+"\x00"+p.Available], a.DelayDays, s.now()) {
				waiting++
				continue
			}
			var r proto.WingetResult
			err := s.call(ctx, d.ID, t.CreatedBy, kind, upgrade(p.ID), &r, 27*time.Minute)
			if err == nil && r.ExitCode == 0 {
				updated++
				done = append(done, fmt.Sprintf("%s %s → %s", p.ID, p.Version, p.Available))
				continue
			}
			if err == nil && name == "winget" && wingetCannotUpdate(r.ExitCode) {
				skipped++
				s.taskAudit(ctx, t, d, "software.upgrade", "winget cannot update %s on %q (code 0x%X): %s", p.ID, d.Hostname, uint32(r.ExitCode), clip(r.Output, 300)) // #nosec G115 -- exit codes are 32-bit
				continue
			}
			failed++
			if err != nil {
				s.taskAudit(ctx, t, d, "software.upgrade", "%s upgrade %s on %q failed: %v", name, p.ID, d.Hostname, err)
			} else {
				s.taskAudit(ctx, t, d, "software.upgrade", "%s upgrade %s on %q: exit code %d\n%s", name, p.ID, d.Hostname, r.ExitCode, clip(r.Output, auditOutput))
			}
		}
		return nil
	}
	if a.Winget {
		if err := source("winget", proto.KindWinget,
			func(string) any { return proto.Winget{Action: proto.WingetUpgrades} },
			func(id string) any { return proto.Winget{Action: proto.WingetUpgrade, ID: id} }); err != nil {
			return taskOutcome{}, err
		}
	}
	if a.Choco {
		if err := source("choco", proto.KindChoco,
			func(string) any { return proto.Choco{Action: proto.ChocoOutdated} },
			func(id string) any { return proto.Choco{Action: proto.ChocoUpgrade, ID: id} }); err != nil {
			return taskOutcome{}, err
		}
	}
	link := s.deviceURL(d, "/software")
	if len(done) > 0 {
		s.taskAudit(ctx, t, d, "software.upgrade", "updated on %q: %s", d.Hostname, strings.Join(done, "; "))
		s.requestInventory(ctx, d.ID)
	}
	if updated+failed+skipped+waiting == 0 {
		return outcome(true, link, "all programs are up to date"), nil
	}
	return outcome(failed == 0, link, "%s programs updated, %s failed, %s skipped (winget cannot update them), %s wait for the update ring", updated, failed, skipped, waiting), nil
}

func init() { taskKinds["apps.update"] = taskAppsUpdate }

// ---- restarts with a deadline

// Restart modes of the Windows Update part.
const (
	RestartNever    = "never"
	RestartAuto     = "auto"     // 5 minutes after the installation
	RestartDeadline = "deadline" // the user is asked; forced at the deadline
)

// restartMode is how a device restarts after updates.
func (p PatchPolicy) restartMode() string {
	switch {
	case p.RestartMode != "":
		return p.RestartMode
	case p.Reboot:
		return RestartAuto
	}
	return RestartNever
}

// noticeEvery is how often a pending restart request is sent to the agent
// again (it may have restarted in between).
const noticeEvery = 30 * time.Minute

type restartNotices struct {
	mu   sync.Mutex
	sent map[int64]time.Time
}

func (n *restartNotices) due(id int64, now time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.sent == nil {
		n.sent = map[int64]time.Time{}
	}
	if now.Sub(n.sent[id]) < noticeEvery {
		return false
	}
	n.sent[id] = now
	return true
}

func (n *restartNotices) forget(id int64) {
	n.mu.Lock()
	delete(n.sent, id)
	n.mu.Unlock()
}

// RunRestarts handles the restarts that policies ask for (monitor loop):
// a device that needs a restart after updates gets a request with a
// deadline, its user is asked by the tray icon, and at the deadline (in the
// maintenance window, if the device has one) the server restarts it.
func (s *Server) RunRestarts(ctx context.Context) {
	pr, err := s.cachedPolicies(ctx)
	if err != nil {
		return
	}
	list, err := s.store.PatchOverview(ctx, nil)
	if err != nil {
		return
	}
	reqs, err := s.store.RestartRequests(ctx)
	if err != nil {
		return
	}
	now := s.now()
	for _, dp := range list {
		u, l := pr.updates(dp.ID, defaultPatchPolicy())
		req, has := reqs[dp.ID]
		if dp.Report == nil || !dp.Report.RebootRequired || u.restartMode() != RestartDeadline {
			if has {
				_ = s.store.DeleteRestartRequest(ctx, dp.ID)
				s.notices.forget(dp.ID)
				if s.Connected(dp.ID) {
					_ = s.call(ctx, dp.ID, "system", proto.KindRestartNotice, proto.RestartNotice{}, nil, actionTimeout)
				}
			}
			continue
		}
		d := &store.Device{ID: dp.ID, Hostname: dp.Hostname}
		if !has {
			req = store.RestartRequest{DeviceID: dp.ID, RequestedAt: now, Deadline: now.Add(time.Duration(u.DeadlineDays) * 24 * time.Hour)}
			if err := s.store.AddRestartRequest(ctx, dp.ID, req.Deadline); err != nil {
				continue
			}
			_ = s.store.Audit(ctx, "system", "", "restart.request", deviceTarget(d),
				fmt.Sprintf("policy %q asks the user of %q to restart by %s", l.Policy.Name, dp.Hostname, req.Deadline.Local().Format("2006-01-02 15:04")))
		}
		if s.Connected(dp.ID) && s.notices.due(dp.ID, now) {
			if err := s.call(ctx, dp.ID, "system", proto.KindRestartNotice, proto.RestartNotice{Deadline: req.Deadline}, nil, actionTimeout); err != nil {
				s.log.Debug("restart notice", "device", dp.ID, "err", err)
			}
		}
		if now.Before(req.Deadline) {
			continue
		}
		if mw, _ := pr.maintenance(dp.ID); mw != nil && len(mw.Windows) > 0 && !mw.active(now.Local()) {
			continue
		}
		if ok, err := s.store.MarkOnce(ctx, "restart:"+strconv.FormatInt(dp.ID, 10), req.Deadline); err != nil || !ok {
			continue
		}
		p := proto.Power{Action: "restart", Delay: 600, Message: "Your administrator restarts this computer in 10 minutes to finish installing updates. Save your work."}
		if _, err := s.queueTask(ctx, d, "policy "+l.Policy.Name, "power", "Restart in %s seconds", []string{"600"}, p); err != nil {
			s.log.Warn("restart deadline", "device", dp.ID, "err", err)
		}
	}
}

// unknownVersion reports whether winget does not know the installed version
// (such packages show as upgradable every day).
func unknownVersion(v string) bool {
	v = strings.TrimSpace(v)
	return v == "" || strings.EqualFold(v, "Unknown") || strings.HasPrefix(v, "<")
}

// wingetCannotUpdate reports winget results that mean the package cannot be
// updated this way (it updates itself, or winget does not know its version):
// not a failure of the policy.
func wingetCannotUpdate(code int) bool {
	switch uint32(code) { // #nosec G115 -- exit codes are 32-bit
	case 0x8A15002B, // no applicable upgrade / version unknown
		0x8A15008E: // install technology differs (for example Microsoft Edge)
		return true
	}
	return false
}
