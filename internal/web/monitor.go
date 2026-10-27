package web

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/store"
)

// RunMonitor checks the alert rules every minute until ctx ends.
func (s *Server) RunMonitor(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	purge := time.Now()
	var required time.Time
	if err := s.MigrateCustomerPolicies(ctx); err != nil {
		s.log.Error("cannot add the Default policies of the customers", "err", err)
	}
	for {
		s.CheckAlerts(ctx)
		s.RunPatchSchedule(ctx)
		s.RunSchedules(ctx)
		s.RunPolicyAutomations(ctx)
		s.RunAppUpdates(ctx)
		s.RunRestarts(ctx)
		s.RunNetChecks(ctx)
		s.RunDiskHealth(ctx)
		if time.Since(required) >= requiredEvery {
			required = time.Now()
			s.RunRequiredSoftware(ctx)
			s.RunBitLocker(ctx)
		}
		s.DispatchTasks(ctx)
		s.RunReports(ctx)
		if time.Since(purge) > 6*time.Hour {
			purge = time.Now()
			if err := s.store.PurgeSamples(ctx, 7*24*time.Hour); err != nil {
				s.log.Warn("cannot purge old samples", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
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
	sctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := sendMail(sctx, e, m.Recipients, subject, body); err != nil {
		s.log.Error("alert email failed", "err", err)
		_ = s.store.Audit(ctx, "-", "server", "alert.email.failed", "settings", "alert email could not be sent: "+err.Error())
		return
	}
	ids := make([]int64, len(opened))
	for i, a := range opened {
		ids[i] = a.ID
	}
	_ = s.store.MarkNotified(ctx, ids)
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
	pr, err := s.loadPolicies(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	m = builtinAlerts(m)
	type window struct{ cpu, mem int }
	rules := map[int64]MonitoringSettings{}
	windows := map[window]bool{{m.CPUMinutes, m.MemMinutes}: true}
	for id := range pr.scopes {
		r, _ := pr.alerts(id, m)
		rules[id] = r
		windows[window{r.CPUMinutes, r.MemMinutes}] = true
	}
	var all []store.MonitorState
	var conds []store.Condition
	keep := map[int64]bool{}
	for w := range windows {
		states, err := s.store.MonitorStates(ctx, time.Duration(w.cpu)*time.Minute, time.Duration(w.mem)*time.Minute)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, st := range states {
			r, ok := rules[st.ID]
			if !ok {
				r = m
			}
			if (window{r.CPUMinutes, r.MemMinutes}) != w {
				continue
			}
			all = append(all, st)
			c, k := evaluate(r, []store.MonitorState{st}, s.now())
			conds = append(conds, c...)
			for id := range k {
				keep[id] = true
			}
		}
	}
	conds = append(conds, s.healthConditions(ctx, pr, rules)...)
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
