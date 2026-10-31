package web

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/store"
)

// Monitors of policies: events of the Windows event logs (at least Count
// matching events within Minutes) and processes that must run. The server
// asks the devices every monitorEvery and keeps the last result per device,
// which opens and resolves the alerts.

// MonitorPolicy is the Monitors part of a policy.
type MonitorPolicy struct {
	Events    []EventRule   `json:"events,omitempty"`
	Processes []ProcessRule `json:"processes,omitempty"`
}

// EventRule alerts when at least Count events match within Minutes.
type EventRule struct {
	Name     string `json:"name"`
	Log      string `json:"log"`
	IDs      []int  `json:"ids,omitempty"`
	Source   string `json:"source,omitempty"`
	Level    int    `json:"level,omitempty"`
	Count    int    `json:"count"`
	Minutes  int    `json:"minutes"`
	Severity string `json:"severity"`
}

// IDText is the IDs as the form shows them.
func (e EventRule) IDText() string {
	s := make([]string, len(e.IDs))
	for i, id := range e.IDs {
		s[i] = strconv.Itoa(id)
	}
	return strings.Join(s, ", ")
}

// ProcessRule alerts when the process does not run.
type ProcessRule struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
}

const (
	monitorEvery = 5 * time.Minute
	// monitorVersion is the first agent with monitors.
	monitorVersion = "0.12.0"
	AlertEvent     = "event"
	AlertProcess   = "process"
)

func init() {
	alertTitles[AlertEvent] = "Event log"
	alertTitles[AlertProcess] = "Process not running"
}

func (m *MonitorPolicy) validate() error {
	if len(m.Events) > proto.MaxEventMonitors {
		return fmt.Errorf("at most %d event rules", proto.MaxEventMonitors)
	}
	if len(m.Processes) > proto.MaxProcessMonitors {
		return fmt.Errorf("at most %d process rules", proto.MaxProcessMonitors)
	}
	seen := map[string]bool{}
	for _, e := range m.Events {
		if n := len(strings.TrimSpace(e.Name)); n < 1 || n > 60 {
			return errors.New("each event rule needs a name (up to 60 characters)")
		}
		if k := strings.ToLower(e.Name); seen[k] {
			return errors.New("each event rule needs its own name")
		} else {
			seen[k] = true
		}
		if err := e.monitor().Valid(); err != nil {
			return err
		}
		if e.Count < 1 || e.Count > 10000 {
			return errors.New("an event rule needs 1–10000 events")
		}
		if e.Severity != "warning" && e.Severity != "critical" {
			return errors.New("unknown severity")
		}
	}
	seen = map[string]bool{}
	for _, p := range m.Processes {
		n := strings.TrimSpace(p.Name)
		if n == "" || len(n) > 100 || strings.ContainsAny(n, `\/:*?"<>|`) {
			return errors.New("a process rule needs a program name like sqlservr.exe")
		}
		if k := strings.TrimSuffix(strings.ToLower(n), ".exe"); seen[k] {
			return errors.New("each process is watched once")
		} else {
			seen[k] = true
		}
		if p.Severity != "warning" && p.Severity != "critical" {
			return errors.New("unknown severity")
		}
	}
	return nil
}

func (e EventRule) monitor() proto.EventMonitor {
	return proto.EventMonitor{Key: e.Name, Log: e.Log, IDs: e.IDs, Source: e.Source, Level: e.Level, Minutes: e.Minutes}
}

// parseEventIDs reads "4625, 4740".
func parseEventIDs(s string) ([]int, error) {
	var out []int
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		n, err := strconv.Atoi(f)
		if err != nil || n < 0 || n > 65535 {
			return nil, fmt.Errorf("%q is not an event ID", f)
		}
		out = append(out, n)
	}
	return out, nil
}

func (pr *policyResolver) monitors(deviceID int64) (*MonitorPolicy, *policyLevel) {
	if l := pr.part(deviceID, func(p *PolicySettings) bool { return p.Monitors != nil }); l != nil {
		return l.Settings.Monitors, l
	}
	return nil, nil
}

// monitorRunner allows one round of checks at a time.
type monitorRunner struct {
	mu   sync.Mutex
	busy bool
	last time.Time
}

// RunMonitorChecks asks the connected devices with monitors for their
// results every monitorEvery (monitor loop; in the background).
func (s *Server) RunMonitorChecks(ctx context.Context) {
	pr, err := s.cachedPolicies(ctx)
	if err != nil {
		return
	}
	type job struct {
		id  int64
		run proto.MonitorRun
	}
	var jobs []job
	var keep []int64
	for id, sc := range pr.scopes {
		m, _ := pr.monitors(id)
		if m == nil || (len(m.Events) == 0 && len(m.Processes) == 0) {
			continue
		}
		keep = append(keep, id)
		if !s.Connected(id) {
			continue
		}
		j := job{id: id}
		if isWindowsOS(sc.OS) {
			for _, e := range m.Events {
				j.run.Events = append(j.run.Events, e.monitor())
			}
		}
		for _, p := range m.Processes {
			j.run.Processes = append(j.run.Processes, strings.TrimSpace(p.Name))
		}
		if len(j.run.Events)+len(j.run.Processes) > 0 {
			jobs = append(jobs, j)
		}
	}
	_ = s.store.ClearMonitorResults(ctx, keep)
	s.monitors.mu.Lock()
	if s.monitors.busy || len(jobs) == 0 || s.now().Sub(s.monitors.last) < monitorEvery-30*time.Second {
		s.monitors.mu.Unlock()
		return
	}
	s.monitors.busy, s.monitors.last = true, s.now()
	s.monitors.mu.Unlock()
	go func() { // #nosec G118 -- outlives the monitor tick on purpose; own timeouts
		defer func() { s.monitors.mu.Lock(); s.monitors.busy = false; s.monitors.mu.Unlock() }()
		ctx := context.Background()
		var wg sync.WaitGroup
		sem := make(chan struct{}, 16)
		for _, j := range jobs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				s.checkMonitors(ctx, j.id, j.run)
			}()
		}
		wg.Wait()
		s.CheckAlerts(ctx)
	}()
}

// checkMonitors asks one device and stores the answer.
func (s *Server) checkMonitors(ctx context.Context, id int64, run proto.MonitorRun) {
	var res proto.MonitorResults
	if err := s.call(ctx, id, "system", proto.KindMonitorCheck, run, &res, 2*time.Minute); err != nil {
		s.log.Debug("monitors", "device", id, "err", err)
		return
	}
	var list []store.MonitorResult
	for _, e := range res.Events {
		list = append(list, store.MonitorResult{Kind: AlertEvent, Key: e.Key, Count: e.Count, Error: clip(e.Error, 300)})
	}
	for _, p := range res.Processes {
		list = append(list, store.MonitorResult{Kind: AlertProcess, Key: p.Name, OK: p.Running})
	}
	if err := s.store.SaveMonitorResults(ctx, id, list); err != nil {
		s.log.Warn("monitors: cannot store", "device", id, "err", err)
	}
}

// monitorConditions are the alerts of the stored results under the
// devices' current rules.
func (s *Server) monitorConditions(ctx context.Context, pr *policyResolver) []store.Condition {
	results, err := s.store.MonitorResults(ctx, 0)
	if err != nil {
		return nil
	}
	var conds []store.Condition
	for _, r := range results {
		m, _ := pr.monitors(r.DeviceID)
		if m == nil {
			continue
		}
		switch r.Kind {
		case AlertEvent:
			for _, e := range m.Events {
				if e.Name == r.Key && r.Error == "" && r.Count >= e.Count {
					conds = append(conds, store.Condition{DeviceID: r.DeviceID, Kind: AlertEvent, Key: e.Name, Severity: e.Severity,
						Message: fmt.Sprintf("%s: %d events in the %s log within %d minutes%s", e.Name, r.Count, e.Log, e.Minutes, idNote(e))})
				}
			}
		case AlertProcess:
			for _, p := range m.Processes {
				if proto.SameProcess(p.Name, r.Key) && !r.OK {
					conds = append(conds, store.Condition{DeviceID: r.DeviceID, Kind: AlertProcess, Key: p.Name, Severity: p.Severity,
						Message: p.Name + " is not running"})
				}
			}
		}
	}
	return conds
}

func idNote(e EventRule) string {
	if len(e.IDs) == 0 {
		return ""
	}
	return " (IDs " + e.IDText() + ")"
}

// monitorRow is a rule with its last result for the device page.
type monitorRow struct {
	Kind    string
	Name    string
	Detail  string
	OK      bool
	Count   int
	Error   string
	Checked *time.Time
}

// deviceMonitors lists the monitors of a device with their last results.
func (s *Server) deviceMonitors(ctx context.Context, pr *policyResolver, d *store.Device) []monitorRow {
	m, _ := pr.monitors(d.ID)
	if m == nil {
		return nil
	}
	results, _ := s.store.MonitorResults(ctx, d.ID)
	find := func(kind, key string) *store.MonitorResult {
		for i := range results {
			if results[i].Kind == kind && (results[i].Key == key || (kind == AlertProcess && proto.SameProcess(results[i].Key, key))) {
				return &results[i]
			}
		}
		return nil
	}
	var rows []monitorRow
	if d.IsWindows() {
		for _, e := range m.Events {
			row := monitorRow{Kind: AlertEvent, Name: e.Name, Detail: fmt.Sprintf("%s ≥ %d / %d min%s", e.Log, e.Count, e.Minutes, idNote(e))}
			if r := find(AlertEvent, e.Name); r != nil {
				row.Checked, row.Count, row.Error, row.OK = &r.CheckedAt, r.Count, r.Error, r.Error == "" && r.Count < e.Count
			}
			rows = append(rows, row)
		}
	}
	for _, p := range m.Processes {
		row := monitorRow{Kind: AlertProcess, Name: p.Name}
		if r := find(AlertProcess, p.Name); r != nil {
			row.Checked, row.OK = &r.CheckedAt, r.OK
		}
		rows = append(rows, row)
	}
	return rows
}
