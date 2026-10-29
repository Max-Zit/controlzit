package web

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/store"
)

// RunMonitor runs the background work of the server until ctx ends. Each
// part has its own loop, so a slow one (a mail server that does not answer,
// a large report) does not hold up the others.
func (s *Server) RunMonitor(ctx context.Context) {
	if err := s.MigrateCustomerPolicies(ctx); err != nil {
		s.log.Error("cannot add the Default policies of the customers", "err", err)
	}
	s.every(ctx, "alerts", time.Minute, s.CheckAlerts)
	s.every(ctx, "patch schedule", time.Minute, s.RunPatchSchedule)
	s.every(ctx, "script schedules", time.Minute, s.RunSchedules)
	s.every(ctx, "policy automations", time.Minute, s.RunPolicyAutomations)
	s.every(ctx, "program updates", time.Minute, s.RunAppUpdates)
	s.every(ctx, "restarts", time.Minute, s.RunRestarts)
	s.every(ctx, "network checks", time.Minute, s.RunNetChecks)
	s.every(ctx, "disk health", time.Minute, s.RunDiskHealth)
	s.every(ctx, "monitors", time.Minute, s.RunMonitorChecks)
	s.every(ctx, "vulnerability scan", time.Minute, s.RunVulnScan)
	s.every(ctx, "required software", requiredEvery, func(ctx context.Context) {
		s.RunRequiredSoftware(ctx)
		s.RunBitLocker(ctx)
	})
	s.every(ctx, "tasks", time.Minute, s.DispatchTasks)
	s.every(ctx, "reports", time.Minute, s.RunReports)
	s.every(ctx, "metric history", 10*time.Minute, s.RunMetricHistory)
	s.every(ctx, "console backup", time.Minute, s.RunBackups)
	<-ctx.Done()
}

// every runs fn now and then every interval in its own goroutine until ctx
// ends; runs of one loop never overlap. A panic is logged and the loop goes
// on with its next run.
func (s *Server) every(ctx context.Context, name string, interval time.Duration, fn func(context.Context)) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			func() {
				defer func() {
					if r := recover(); r != nil {
						s.log.Error("background work failed", "part", name, "panic", fmt.Sprint(r))
					}
				}()
				fn(ctx)
			}()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// CheckAlerts evaluates the rules once and sends the notifications.
func (s *Server) CheckAlerts(ctx context.Context) {
	s.alerts.Lock()
	defer s.alerts.Unlock()
	m := s.Monitoring(ctx)
	states, conds, keep, err := s.evaluatePolicies(ctx, m)
	if err != nil {
		s.log.Error("monitor: cannot load devices", "err", err)
		return
	}
	opened, resolved, err := s.store.SyncAlerts(ctx, conds, keep)
	if err != nil {
		s.log.Error("monitor: cannot update alerts", "err", err)
		return
	}
	if len(opened) == 0 && len(resolved) == 0 {
		return
	}
	names := map[int64]store.MonitorState{}
	for _, d := range states {
		names[d.ID] = d
	}
	s.notifyChannels(ctx, opened, resolved, names)
	if len(opened) == 0 && !m.EmailOnResolve {
		return
	}
	for _, a := range opened {
		d := names[a.DeviceID]
		s.log.Info("alert opened", "device", d.Hostname, "kind", a.Kind, "key", a.Key, "message", a.Message)
	}
	if !m.EmailOnOpen || len(m.Recipients) == 0 {
		return
	}
	var send []store.Alert
	send = append(send, opened...)
	if m.EmailOnResolve {
		send = append(send, resolved...)
	}
	if len(send) == 0 {
		return
	}
	e := s.Email(ctx)
	if !e.Configured() {
		return
	}
	subject, body := alertEmail(send, names)
	ids := make([]int64, len(opened))
	for i, a := range opened {
		ids[i] = a.ID
	}
	// The mail goes out in the background: a slow mail server must not hold
	// the alert check (and everything waiting for its lock).
	go func() { // #nosec G118 -- the mail outlives this check; own timeout
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if err := sendMail(ctx, e, m.Recipients, subject, body); err != nil {
			s.log.Error("alert email failed", "err", err)
			_ = s.store.Audit(ctx, "-", "server", "alert.email.failed", "settings", "alert email could not be sent: "+err.Error())
			return
		}
		_ = s.store.MarkNotified(ctx, ids)
	}()
}

// alertEmail writes the notification text.
func alertEmail(alerts []store.Alert, devs map[int64]store.MonitorState) (subject, body string) {
	open, crit := 0, 0
	for _, a := range alerts {
		if a.ResolvedAt == nil {
			open++
			if a.Severity == "critical" {
				crit++
			}
		}
	}
	switch {
	case open == 0:
		subject = fmt.Sprintf("ControlZit: %d alert(s) resolved", len(alerts))
	case len(alerts) == 1:
		a := alerts[0]
		subject = fmt.Sprintf("ControlZit %s: %s on %s", a.Severity, alertTitles[a.Kind], devs[a.DeviceID].Hostname)
	default:
		subject = fmt.Sprintf("ControlZit: %d new alert(s), %d critical", open, crit)
	}
	var b strings.Builder
	for _, a := range alerts {
		d := devs[a.DeviceID]
		state := strings.ToUpper(a.Severity)
		if a.ResolvedAt != nil {
			state = "RESOLVED"
		}
		title := alertTitles[a.Kind]
		if a.Key != "" {
			title += " (" + a.Key + ")"
		}
		fmt.Fprintf(&b, "[%s] %s\n  Device:   %s\n  Customer: %s / %s\n  Details:  %s\n  Since:    %s\n\n",
			state, title, d.Hostname, d.Customer, d.Site, a.Message, a.OpenedAt.Local().Format("2006-01-02 15:04"))
	}
	b.WriteString("-- \nControlZit · sent because alert emails are switched on in Settings → Monitoring.\n")
	return subject, b.String()
}

// evaluatePolicies applies to each device the alert rules of its policy (or
// the built-in ones). The load averages are computed per rule window.
func (s *Server) evaluatePolicies(ctx context.Context, m MonitoringSettings) ([]store.MonitorState, []store.Condition, map[int64]bool, error) {
	pr, err := s.cachedPolicies(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	m = builtinAlerts(m)
	rules := map[int64]MonitoringSettings{}
	windows := map[int64]store.LoadWindow{}
	for id := range pr.scopes {
		r, _ := pr.alerts(id, m)
		rules[id] = r
		windows[id] = store.LoadWindow{CPUMinutes: r.CPUMinutes, MemMinutes: r.MemMinutes}
	}
	all, err := s.store.MonitorStates(ctx, store.LoadWindow{CPUMinutes: m.CPUMinutes, MemMinutes: m.MemMinutes}, windows)
	if err != nil {
		return nil, nil, nil, err
	}
	var conds []store.Condition
	keep := map[int64]bool{}
	for _, st := range all {
		r, ok := rules[st.ID]
		if !ok {
			r = m
		}
		c, k := evaluate(r, []store.MonitorState{st}, s.now())
		conds = append(conds, c...)
		for id := range k {
			keep[id] = true
		}
	}
	conds = append(conds, s.healthConditions(ctx, pr, rules)...)
	conds = append(conds, s.blockedConditions(ctx, pr)...)
	conds = append(conds, s.vulnConditions(ctx, rules)...)
	conds = append(conds, s.forecastConditions(rules, m)...)
	conds = append(conds, s.monitorConditions(ctx, pr)...)
	// Devices in a quiet maintenance window open no new alerts; their open
	// alerts stay as they are.
	now := s.now().Local()
	quiet := map[int64]bool{}
	for id := range pr.scopes {
		if mw, _ := pr.maintenance(id); mw != nil && mw.Quiet && mw.active(now) {
			quiet[id], keep[id] = true, true
		}
	}
	if len(quiet) > 0 {
		conds = slices.DeleteFunc(conds, func(c store.Condition) bool { return quiet[c.DeviceID] })
	}
	return all, conds, keep, nil
}
