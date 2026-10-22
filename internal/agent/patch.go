package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
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

// scanDue reports whether the periodic scan should run.
func (a *Agent) scanDue() bool {
	a.patch.mu.Lock()
	defer a.patch.mu.Unlock()
	return !a.patch.busy && time.Since(a.patch.report.ScannedAt) > patchScanEvery
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
	a.patch.busy = true
	a.patch.mu.Unlock()
	go func() {
		defer func() {
			a.patch.mu.Lock()
			a.patch.busy = false
			a.patch.mu.Unlock()
		}()
		job(a.runCtx)
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
	res, err := PatchInstall(ictx, in.IDs)
	cancel()
	run.Finished = time.Now().UTC()
	if err != nil {
		run.Error = err.Error()
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
	a.scanJob(ctx) // the list changed
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
