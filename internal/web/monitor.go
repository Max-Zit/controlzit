package web

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/store"
)

// RunMonitor checks the alert rules every minute until ctx ends.
func (s *Server) RunMonitor(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	purge := time.Now()
	for {
		s.CheckAlerts(ctx)
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
	m := s.Monitoring(ctx)
	states, err := s.store.MonitorStates(ctx, time.Duration(m.CPUMinutes)*time.Minute, time.Duration(m.MemMinutes)*time.Minute)
	if err != nil {
		s.log.Error("monitor: cannot load devices", "err", err)
		return
	}
	conds, keep := evaluate(m, states, s.now())
	opened, resolved, err := s.store.SyncAlerts(ctx, conds, keep)
	if err != nil {
		s.log.Error("monitor: cannot update alerts", "err", err)
		return
	}
	if len(opened) == 0 && (len(resolved) == 0 || !m.EmailOnResolve) {
		return
	}
	names := map[int64]store.MonitorState{}
	for _, d := range states {
		names[d.ID] = d
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
