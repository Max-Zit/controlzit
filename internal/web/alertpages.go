package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/netacl"
	"github.com/max-zit/controlzit/internal/store"
)

// AlertTitle is the translated name of an alert kind.
func (p *Page) AlertTitle(kind string) string {
	if t, ok := alertTitles[kind]; ok {
		return p.T(t)
	}
	return kind
}

type alertsData struct {
	Alerts []store.Alert
	All    bool
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	all := r.FormValue("all") == "1"
	list, err := s.store.Alerts(r.Context(), userFrom(r), store.AlertFilter{Open: !all})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "alerts", &Page{Title: "Alerts", Nav: "alerts", Data: &alertsData{Alerts: list, All: all}})
}

func (s *Server) handleAlertAck(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	u := userFrom(r)
	if !ok || !u.CanWrite() {
		s.forbidden(w, r)
		return
	}
	_, cust, err := s.store.AlertDevice(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) || err == nil && !u.SeesCustomer(cust) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	a, err := s.store.AckAlert(r.Context(), id, u.Username)
	back := safeNext(r.FormValue("back"))
	if back == "/" {
		back = "/alerts"
	}
	if err != nil {
		s.redirect(w, r, back, "The alert is already acknowledged or resolved.")
		return
	}
	s.audit(r, "alert.ack", "device:"+strconv.FormatInt(a.DeviceID, 10), "acknowledged alert %s %s: %s", a.Kind, a.Key, a.Message)
	s.redirect(w, r, back, "Alert acknowledged.")
}

// ---- settings: monitoring and email

type monitoringData struct {
	M        MonitoringSettings
	E        EmailSettings
	HasPass  bool
	Services string
	To       string
}

func (s *Server) handleMonitoringSettings(w http.ResponseWriter, r *http.Request) {
	s.showMonitoring(w, r, http.StatusOK, s.Monitoring(r.Context()), s.Email(r.Context()), "")
}

func (s *Server) showMonitoring(w http.ResponseWriter, r *http.Request, status int, m MonitoringSettings, e EmailSettings, errMsg string) {
	hasPass := s.Email(r.Context()).Password != ""
	e.Password = ""
	d := &monitoringData{M: m, E: e, HasPass: hasPass, Services: strings.Join(m.WatchServices, "\n"), To: strings.Join(m.Recipients, "\n")}
	if d.E.Port == 0 {
		d.E.Port, d.E.Security = 587, "starttls"
	}
	p := &Page{Title: "Monitoring and alerts", Nav: "settings", Data: d}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "monitoring", p)
}

func formInt(r *http.Request, k string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(r.FormValue(k)))
	return n
}

func lines(s string) []string {
	var out []string
	for _, f := range netacl.Split(s) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func (s *Server) handleMonitoringSave(w http.ResponseWriter, r *http.Request) {
	m := MonitoringSettings{
		CPUPercent: formInt(r, "cpu_percent"), CPUMinutes: formInt(r, "cpu_minutes"), MemPercent: formInt(r, "mem_percent"), MemMinutes: formInt(r, "mem_minutes"),
		DiskPercent: formInt(r, "disk_percent"), DiskMinFreeGB: formInt(r, "disk_min_free_gb"), OfflineMinutes: formInt(r, "offline_minutes"),
		RebootDays: formInt(r, "reboot_days"), DefenderOff: r.FormValue("defender_off") == "1", FirewallOff: r.FormValue("firewall_off") == "1",
		WatchServices: lines(r.FormValue("watch_services")), EmailOnOpen: r.FormValue("email_on_open") == "1",
		EmailOnResolve: r.FormValue("email_on_resolve") == "1", Recipients: lines(r.FormValue("recipients")),
	}
	if err := m.Validate(); err != nil {
		s.showMonitoring(w, r, http.StatusBadRequest, m, s.Email(r.Context()), err.Error())
		return
	}
	if err := s.store.SetSetting(r.Context(), settingMonitoring, m); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.monitoring", "settings", "cpu %d%%/%dmin, memory %d%%/%dmin, disk %d%% or <%d GB, offline %dmin, restart %dd, defender %v, firewall %v, services %v, email %v/%v to %v",
		m.CPUPercent, m.CPUMinutes, m.MemPercent, m.MemMinutes, m.DiskPercent, m.DiskMinFreeGB, m.OfflineMinutes, m.RebootDays, m.DefenderOff, m.FirewallOff,
		m.WatchServices, m.EmailOnOpen, m.EmailOnResolve, m.Recipients)
	go s.CheckAlerts(context.Background())
	s.redirect(w, r, "/settings/monitoring", "Saved.")
}

func (s *Server) emailFromForm(r *http.Request) EmailSettings {
	return EmailSettings{Host: strings.TrimSpace(r.FormValue("host")), Port: formInt(r, "port"), Security: r.FormValue("security"),
		Username: strings.TrimSpace(r.FormValue("username")), Password: r.FormValue("password"), From: strings.TrimSpace(r.FormValue("from"))}
}

func (s *Server) handleEmailSave(w http.ResponseWriter, r *http.Request) {
	e := s.emailFromForm(r)
	if err := s.SaveEmail(r.Context(), e); err != nil {
		s.showMonitoring(w, r, http.StatusBadRequest, s.Monitoring(r.Context()), e, err.Error())
		return
	}
	s.audit(r, "settings.email", "settings", "SMTP %s:%d (%s), user %q, from %q", e.Host, e.Port, e.Security, e.Username, e.From)
	s.redirect(w, r, "/settings/monitoring", "Saved.")
}

func (s *Server) handleEmailTest(w http.ResponseWriter, r *http.Request) {
	m := s.Monitoring(r.Context())
	e := s.Email(r.Context())
	to := m.Recipients
	if len(to) == 0 {
		s.redirect(w, r, "/settings/monitoring", "Add at least one recipient for alert emails first.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	err := sendMail(ctx, e, to, "ControlZit test email", "This is a test email from the ControlZit console.\nAlert emails will arrive like this one.\n")
	if err != nil {
		s.audit(r, "settings.email.test", "settings", "test email failed: %v", err)
		s.redirect(w, r, "/settings/monitoring", "The test email failed: "+err.Error())
		return
	}
	s.audit(r, "settings.email.test", "settings", "test email sent to %v", to)
	s.redirect(w, r, "/settings/monitoring", "Test email sent.")
}
