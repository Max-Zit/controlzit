package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
)

// Windows Update: scans run every patchScanEvery and on request,
// installations run in the background; every change of the state is sent to
// the server as a patch report (again after a reconnect). The last report is
// kept on disk so a restart does not cause a new scan.

const (
	patchScanEvery  = 12 * time.Hour
	patchScanLimit  = 30 * time.Minute
	patchInstallMax = 4 * time.Hour
	patchFile       = "patches.json"
)

type patchState struct {
	mu     sync.Mutex
	report proto.PatchReport
	dirty  bool
	busy   bool
	cancel context.CancelFunc // stops the running scan or installation
	notify chan struct{}
}

func (a *Agent) initPatches() {
	a.patch = &patchState{notify: make(chan struct{}, 1), report: proto.PatchReport{State: proto.PatchIdle}}
	raw, err := os.ReadFile(filepath.Join(a.Dir, patchFile)) // #nosec G304 -- our own data directory
	if err == nil && json.Unmarshal(raw, &a.patch.report) == nil {
		a.patch.report.State = proto.PatchIdle // a job does not survive a restart
		if a.patch.report.Install != nil && a.patch.report.Install.Finished.IsZero() {
			a.patch.report.Install.Finished = time.Now()
			a.patch.report.Install.Error = "the agent was restarted during the installation"
		}
	}
	a.patch.dirty = !a.patch.report.ScannedAt.IsZero()
}

// changePatches updates the report under the lock, saves it and queues it.
func (a *Agent) changePatches(f func(r *proto.PatchReport)) {
	p := a.patch
	p.mu.Lock()
	f(&p.report)
	p.dirty = true
	raw, _ := json.Marshal(p.report)
	p.mu.Unlock()
	if err := os.WriteFile(filepath.Join(a.Dir, patchFile), raw, 0o600); err != nil {
		a.Log.Warn("cannot save the update state", "err", err)
	}
	select {
	case p.notify <- struct{}{}:
	default:
	}
}

// pendingPatchReport returns the report if it has not been sent yet.
func (a *Agent) pendingPatchReport() *proto.PatchReport {
	p := a.patch
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.dirty {
		return nil
	}
	p.dirty = false
	r := p.report
	return &r
}

func (a *Agent) markPatchesUnsent() {
	a.patch.mu.Lock()
	a.patch.dirty = !a.patch.report.ScannedAt.IsZero() || a.patch.report.State != proto.PatchIdle
	a.patch.mu.Unlock()
}

// scanDue reports whether the periodic scan should run: also at once after
// the restart that a scan asked for, so the console sees it is done.
func (a *Agent) scanDue() bool {
	var boot time.Time
	if a.Info != nil {
		boot = a.Info().BootTime
	}
	a.patch.mu.Lock()
	defer a.patch.mu.Unlock()
	r := &a.patch.report
	restarted := r.RebootRequired && boot.After(r.ScannedAt)
	return !a.patch.busy && (restarted || time.Since(r.ScannedAt) > patchScanEvery)
}

// PatchScan and PatchInstall talk to Windows Update (tests replace them).
var (
	PatchScan    = patchScan
	PatchInstall = patchInstall
)

var errPatchBusy = errors.New("the agent is already scanning or installing updates; try again when it has finished")

// startPatchJob runs job in the background unless another one runs.
func (a *Agent) startPatchJob(job func(ctx context.Context)) error {
	a.patch.mu.Lock()
	if a.patch.busy {
		a.patch.mu.Unlock()
		return errPatchBusy
	}
	ctx, cancel := context.WithCancel(a.runCtx)
	a.patch.busy, a.patch.cancel = true, cancel
	a.patch.mu.Unlock()
	go func() {
		defer func() {
			a.patch.mu.Lock()
			a.patch.busy, a.patch.cancel = false, nil
			a.patch.mu.Unlock()
			cancel()
		}()
		job(ctx)
	}()
	return nil
}

func (a *Agent) scanJob(ctx context.Context) {
	a.changePatches(func(r *proto.PatchReport) { r.State = proto.PatchScanning })
	sctx, cancel := context.WithTimeout(ctx, patchScanLimit)
	defer cancel()
	res, err := PatchScan(sctx)
	a.changePatches(func(r *proto.PatchReport) {
		r.State = proto.PatchIdle
		if err != nil {
			r.ScanError = err.Error()
			if ctx.Err() != nil && a.runCtx.Err() == nil {
				r.ScanError = errStoppedByConsole.Error()
			}
			return
		}
		r.ScanError = ""
		r.ScannedAt = time.Now().UTC()
		r.Updates, r.History, r.RebootRequired = res.Updates, res.History, res.RebootRequired
	})
	if err != nil {
		a.Log.Warn("Windows Update scan failed", "err", err)
	} else {
		a.Log.Info("Windows Update scan done", "missing", len(res.Updates), "reboot_required", res.RebootRequired)
	}
}

func (a *Agent) installJob(ctx context.Context, in proto.PatchInstall) {
	run := &proto.PatchInstallRun{By: in.By, Started: time.Now().UTC(), Requested: len(in.IDs)}
	a.changePatches(func(r *proto.PatchReport) {
		r.State = proto.PatchInstalling
		cp := *run
		r.Install = &cp
	})
	a.Log.Info("installing Windows updates", "count", len(in.IDs), "by", in.By)
	ictx, cancel := context.WithTimeout(ctx, patchInstallMax)
	res, err := PatchInstall(ictx, a.currentDefinitions(ictx, in.IDs))
	cancel()
	run.Finished = time.Now().UTC()
	if err != nil {
		run.Error = err.Error()
		if ctx.Err() != nil && a.runCtx.Err() == nil {
			run.Error = errStoppedByConsole.Error()
		}
	} else {
		run.Result, run.RebootRequired, run.Results = res.Result, res.RebootRequired, res.Results
	}
	if run.RebootRequired && in.Reboot {
		if err := scheduleRestart(5*time.Minute, "Windows updates were installed. The computer restarts in 5 minutes; save your work."); err != nil {
			a.Log.Warn("cannot schedule the restart after updates", "err", err)
		} else {
			run.Rebooting = true
		}
	}
	a.Log.Info("Windows updates installed", "result", run.Result, "reboot_required", run.RebootRequired, "err", run.Error)
	a.changePatches(func(r *proto.PatchReport) { r.Install = run })
	a.scanJob(a.runCtx) // the list changed (also after a stop from the console)
}

// currentDefinitions swaps requested definition updates (Defender) for the
// ones Windows Update offers now: every new definition version has its own
// update ID and comes out several times a day, so the ID of the last scan
// is usually gone by the time someone installs it.
func (a *Agent) currentDefinitions(ctx context.Context, ids []string) []string {
	a.patch.mu.Lock()
	known := map[string]proto.PatchUpdate{}
	for _, u := range a.patch.report.Updates {
		known[strings.ToLower(u.ID)] = u
	}
	a.patch.mu.Unlock()
	defs := false
	for _, id := range ids {
		if u, ok := known[strings.ToLower(id)]; ok && u.Definitions() && u.KB != "" {
			defs = true
		}
	}
	if !defs {
		return ids
	}
	sctx, cancel := context.WithTimeout(ctx, patchScanLimit)
	defer cancel()
	now, err := PatchScan(sctx)
	if err != nil {
		a.Log.Warn("Windows Update scan before installing definitions failed", "err", err)
		return ids
	}
	offered := map[string]bool{}
	byKB := map[string]string{}
	for _, u := range now.Updates {
		offered[strings.ToLower(u.ID)] = true
		if u.Definitions() && u.KB != "" {
			byKB[u.KB] = u.ID
		}
	}
	out := make([]string, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		if u, ok := known[strings.ToLower(id)]; ok && !offered[strings.ToLower(id)] && u.Definitions() {
			if cur, ok := byKB[u.KB]; ok {
				a.Log.Info("installing the current definition update instead", "requested", u.Title, "id", cur)
				id = cur
			}
		}
		if !seen[strings.ToLower(id)] {
			seen[strings.ToLower(id)] = true
			out = append(out, id)
		}
	}
	return out
}

func init() {
	register(proto.KindPatchScan, func(context.Context, json.RawMessage) (any, error) {
		if self == nil || self.patch == nil {
			return nil, errors.New("the agent is not running")
		}
		return nil, self.startPatchJob(self.scanJob)
	})
	register(proto.KindPatchInstall, func(_ context.Context, raw json.RawMessage) (any, error) {
		var in proto.PatchInstall
		if err := args(raw, &in); err != nil {
			return nil, err
		}
		if len(in.IDs) == 0 || len(in.IDs) > proto.MaxPatchInstall || len(in.By) > 120 {
			return nil, errors.New("bad list of updates")
		}
		for _, id := range in.IDs {
			if !proto.ValidUpdateID(id) {
				return nil, errors.New("bad list of updates")
			}
		}
		if self == nil || self.patch == nil {
			return nil, errors.New("the agent is not running")
		}
		return nil, self.startPatchJob(func(ctx context.Context) { self.installJob(ctx, in) })
	})
}

// PatchScanResult is what a scan finds.
type PatchScanResult struct {
	Updates        []proto.PatchUpdate      `json:"updates"`
	History        []proto.PatchHistoryItem `json:"history"`
	RebootRequired bool                     `json:"reboot"`
}

// PatchInstallResult is what an installation did.
type PatchInstallResult struct {
	Result         int                 `json:"result"`
	RebootRequired bool                `json:"reboot"`
	Results        []proto.PatchResult `json:"results"`
}

var errStoppedByConsole = errors.New("stopped from the console")

func init() {
	register(proto.KindPatchCancel, func(context.Context, json.RawMessage) (any, error) {
		if self == nil || self.patch == nil {
			return nil, errors.New("the agent is not running")
		}
		self.patch.mu.Lock()
		cancel := self.patch.cancel
		self.patch.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		return map[string]bool{"stopped": cancel != nil}, nil
	})
}
