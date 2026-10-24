package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/store"
)

// Reports: the state of a customer's devices over a period — devices,
// Windows updates, alerts and technician activity. The console shows them
// as a printable page (the browser saves it as PDF) and emails them on a
// schedule to each customer's recipients.

const settingReports = "reports"

// ReportSettings control the emailed reports.
type ReportSettings struct {
	Mode string `json:"mode"` // off, weekly, monthly
	// Day is the weekday (weekly, 0 Sunday) or the day of the month (1–28).
	Day  int `json:"day"`
	Hour int `json:"hour"`
	// Recipients per customer ID; Copy gets every customer's report.
	Recipients map[string][]string `json:"recipients"`
	Copy       []string            `json:"copy"`
	// Language of the emailed reports.
	Language string `json:"language"`
	// LastRun is the period last sent (2026-W43 or 2026-10).
	LastRun string `json:"last_run"`
}

// Reports loads the report settings.
func (s *Server) Reports(ctx context.Context) ReportSettings {
	x := ReportSettings{Mode: "off", Day: 1, Hour: 7}
	if err := s.store.GetSetting(ctx, settingReports, &x); err != nil {
		return ReportSettings{Mode: "off", Day: 1, Hour: 7}
	}
	return x
}

// Report is the content of one report.
type Report struct {
	Customer   string
	CustomerID int64
	Days       int
	From, To   time.Time
	Devices    []reportDevice
	Online     int
	Offline7   int // not seen for more than 7 days
	OS         []store.Counted
	// Windows updates
	UpToDate, Missing, Security, Reboot, NoReport int
	Updates                                       int // missing updates in total
	Alerts                                        *store.AlertStats
	Activity                                      map[string]int
	Outdated                                      int // agents older than the installer
}

type reportDevice struct {
	*store.Device
	Online     bool
	Missing    int
	Security   int
	Reboot     bool
	Searched   bool
	OpenAlerts int
}

// Count returns an activity count (template).
func (r *Report) Count(action string) int { return r.Activity[action] }

// AlertTitle names an alert kind (template).
func (r *Report) AlertTitle(kind string) string {
	if t, ok := alertTitles[kind]; ok {
		return t
	}
	return kind
}

// buildReport collects a report of a customer (0: all customers u may see).
func (s *Server) buildReport(ctx context.Context, u *store.User, customerID int64, days int) (*Report, error) {
	now := s.now()
	rep := &Report{CustomerID: customerID, Days: days, From: now.AddDate(0, 0, -days), To: now}
	if customerID != 0 {
		c, err := s.store.Customer(ctx, customerID)
		if err != nil {
			return nil, err
		}
		if u != nil && !u.SeesCustomer(customerID) {
			return nil, store.ErrNotFound
		}
		rep.Customer = c.Name
	}
	all, err := s.store.PatchOverview(ctx, u)
	if err != nil {
		return nil, err
	}
	open, err := s.store.OpenAlertsByDevice(ctx)
	if err != nil {
		return nil, err
	}
	pkg := s.packages()
	os := map[string]int{}
	var ids []int64
	for _, dp := range all {
		if customerID != 0 && dp.CustomerID != customerID {
			continue
		}
		d := reportDevice{Device: dp.Device, Online: s.Connected(dp.ID), OpenAlerts: open[dp.ID]}
		ids = append(ids, dp.ID)
		if d.Online {
			rep.Online++
		}
		if dp.LastSeenAt == nil || now.Sub(*dp.LastSeenAt) > 7*24*time.Hour {
			rep.Offline7++
		}
		name := dp.OS
		if name == "" {
			name = "unknown"
		}
		os[name]++
		if pkg.Offers(dp.Device) {
			rep.Outdated++
		}
		if r := dp.Report; r != nil && !r.ScannedAt.IsZero() {
			d.Searched = true
			d.Missing, d.Reboot = len(r.Updates), r.RebootRequired
			for i := range r.Updates {
				if r.Updates[i].Security() {
					d.Security++
				}
			}
			rep.Updates += d.Missing
			switch {
			case d.Security > 0:
				rep.Security++
				rep.Missing++
			case d.Missing > 0:
				rep.Missing++
			default:
				rep.UpToDate++
			}
			if d.Reboot {
				rep.Reboot++
			}
		} else {
			rep.NoReport++
		}
		rep.Devices = append(rep.Devices, d)
	}
	for n, c := range os {
		rep.OS = append(rep.OS, store.Counted{Name: n, Count: c})
	}
	sort.Slice(rep.OS, func(i, j int) bool {
		return rep.OS[i].Count > rep.OS[j].Count || rep.OS[i].Count == rep.OS[j].Count && rep.OS[i].Name < rep.OS[j].Name
	})
	if ids == nil {
		ids = []int64{}
	}
	if rep.Alerts, err = s.store.ReportAlerts(ctx, ids, rep.From); err != nil {
		return nil, err
	}
	if rep.Activity, err = s.store.ReportActivity(ctx, ids, rep.From); err != nil {
		return nil, err
	}
	return rep, nil
}

// ---- pages

type reportsData struct {
	Customers []store.Customer
	Days      int
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	cs, err := s.store.Customers(r.Context(), userFrom(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "reports", &Page{Title: "Reports", Nav: "reports", Data: &reportsData{Customers: cs, Days: 30}})
}

func reportDays(v string) int {
	switch n, _ := strconv.Atoi(v); n {
	case 7, 30, 90:
		return n
	}
	return 30
}

func (s *Server) handleReportView(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	cid, _ := strconv.ParseInt(r.FormValue("customer"), 10, 64)
	if cid == 0 && !u.IsAdmin() && !u.AllCustomers {
		s.forbidden(w, r)
		return
	}
	rep, err := s.buildReport(r.Context(), u, cid, reportDays(r.FormValue("days")))
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "report.view", "customer:"+strconv.FormatInt(cid, 10), "viewed the %d-day report of %q", rep.Days, reportName(rep))
	s.render(w, r, http.StatusOK, "reportview", &Page{Title: "Report", Nav: "reports", Data: rep})
}

func reportName(rep *Report) string {
	if rep.Customer == "" {
		return "all customers"
	}
	return rep.Customer
}

// ---- settings and email

type reportSettingsData struct {
	S         ReportSettings
	Customers []store.Customer
	Days      []int
	Hours     []int
	Emailing  bool
}

// Emails returns a customer's recipients as one line (template).
func (x ReportSettings) Emails(id int64) string {
	return strings.Join(x.Recipients[strconv.FormatInt(id, 10)], ", ")
}

func (s *Server) handleReportSettings(w http.ResponseWriter, r *http.Request) {
	cs, err := s.store.Customers(r.Context(), userFrom(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	hours := make([]int, 24)
	for i := range hours {
		hours[i] = i
	}
	e := s.Email(r.Context())
	s.render(w, r, http.StatusOK, "reportsettings", &Page{Title: "Reports", Nav: "settings",
		Data: &reportSettingsData{S: s.Reports(r.Context()), Customers: cs, Days: weekdays, Hours: hours, Emailing: e.Configured()}})
}

// parseEmails splits a list of addresses (commas, semicolons, spaces).
func parseEmails(v string) ([]string, error) {
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' }) {
		a, err := mail.ParseAddress(f)
		if err != nil {
			return nil, fmt.Errorf("%q is not an email address", f)
		}
		out = append(out, a.Address)
	}
	if len(out) > 20 {
		return nil, errors.New("at most 20 addresses")
	}
	return out, nil
}

func (s *Server) handleReportSettingsSave(w http.ResponseWriter, r *http.Request) {
	old := s.Reports(r.Context())
	x := ReportSettings{Mode: r.FormValue("mode"), Recipients: map[string][]string{}, LastRun: old.LastRun, Language: r.FormValue("language")}
	if !validLang(x.Language) {
		x.Language = "en"
	}
	x.Day, _ = strconv.Atoi(r.FormValue("weekday"))
	if x.Mode == "monthly" {
		x.Day, _ = strconv.Atoi(r.FormValue("monthday"))
	}
	x.Hour, _ = strconv.Atoi(r.FormValue("hour"))
	back := "/settings/reports"
	if (x.Mode != "off" && x.Mode != "weekly" && x.Mode != "monthly") || x.Hour < 0 || x.Hour > 23 ||
		(x.Mode == "weekly" && (x.Day < 0 || x.Day > 6)) || (x.Mode == "monthly" && (x.Day < 1 || x.Day > 28)) {
		s.redirect(w, r, back, "Unknown action.")
		return
	}
	var err error
	if x.Copy, err = parseEmails(r.FormValue("copy")); err != nil {
		s.redirect(w, r, back, err.Error())
		return
	}
	cs, err := s.store.Customers(r.Context(), userFrom(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, c := range cs {
		id := strconv.FormatInt(c.ID, 10)
		list, err := parseEmails(r.FormValue("to_" + id))
		if err != nil {
			s.redirect(w, r, back, c.Name+": "+err.Error())
			return
		}
		if len(list) > 0 {
			x.Recipients[id] = list
		}
	}
	if err := s.store.SetSetting(r.Context(), settingReports, x); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.reports", "settings", "reports: %s, day %d, %02d:00, %d customers with recipients, copy to %v", x.Mode, x.Day, x.Hour, len(x.Recipients), x.Copy)
	s.redirect(w, r, back, "Saved.")
}

// handleReportSend emails one customer's report now (to check the setup).
func (s *Server) handleReportSend(w http.ResponseWriter, r *http.Request) {
	cid, _ := strconv.ParseInt(r.FormValue("customer"), 10, 64)
	back := "/settings/reports"
	x := s.Reports(r.Context())
	to := append(append([]string{}, x.Recipients[strconv.FormatInt(cid, 10)]...), x.Copy...)
	if len(to) == 0 {
		s.redirect(w, r, back, "This customer has no report recipients.")
		return
	}
	if err := s.emailReport(r.Context(), cid, to, x.Mode); err != nil {
		s.redirect(w, r, back, err.Error())
		return
	}
	s.audit(r, "report.email", "customer:"+strconv.FormatInt(cid, 10), "report emailed to %s", strings.Join(to, ", "))
	s.redirect(w, r, back, translate(s.lang(r, userFrom(r)), "Report sent to %s.", strings.Join(to, ", ")))
}

func modeDays(mode string) int {
	if mode == "monthly" {
		return 30
	}
	return 7
}

// emailReport renders and sends one customer's report.
func (s *Server) emailReport(ctx context.Context, cid int64, to []string, mode string) error {
	rep, err := s.buildReport(ctx, nil, cid, modeDays(mode))
	if err != nil {
		return err
	}
	e := s.Email(ctx)
	lang := s.Reports(ctx).Language
	if !validLang(lang) {
		lang = "en"
	}
	p := &Page{Title: "Report", Lang: lang, Version: s.Version, Data: rep}
	html, err := s.renderString("reportmail", p)
	if err != nil {
		return err
	}
	subject := p.T("ControlZit report: %s, last %d days", reportName(rep), rep.Days)
	text := p.T("The report is in the HTML part of this email.")
	return sendMailHTML(ctx, e, to, subject, text, html)
}

// RunReports emails the scheduled reports that are due (monitor loop).
func (s *Server) RunReports(ctx context.Context) {
	x := s.Reports(ctx)
	now := s.now().Local()
	var period string
	switch x.Mode {
	case "weekly":
		if int(now.Weekday()) != x.Day || now.Hour() != x.Hour {
			return
		}
		y, wk := now.ISOWeek()
		period = fmt.Sprintf("%d-W%02d", y, wk)
	case "monthly":
		if now.Day() != x.Day || now.Hour() != x.Hour {
			return
		}
		period = now.Format("2006-01")
	default:
		return
	}
	if x.LastRun == period {
		return
	}
	x.LastRun = period
	if err := s.store.SetSetting(ctx, settingReports, x); err != nil {
		s.log.Warn("reports: cannot save the run", "err", err)
		return
	}
	cs, err := s.store.Customers(ctx, nil)
	if err != nil {
		s.log.Warn("reports: cannot list customers", "err", err)
		return
	}
	for _, c := range cs {
		to := append(append([]string{}, x.Recipients[strconv.FormatInt(c.ID, 10)]...), x.Copy...)
		if len(to) == 0 {
			continue
		}
		target := "customer:" + strconv.FormatInt(c.ID, 10)
		if err := s.emailReport(ctx, c.ID, to, x.Mode); err != nil {
			s.log.Warn("reports: email failed", "customer", c.Name, "err", err)
			_ = s.store.Audit(ctx, "system", "", "report.email", target, "scheduled report of "+c.Name+" failed: "+err.Error())
			continue
		}
		_ = s.store.Audit(ctx, "system", "", "report.email", target, "scheduled report of "+c.Name+" sent to "+strings.Join(to, ", "))
	}
}
