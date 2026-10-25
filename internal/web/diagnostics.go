package web

import (
	"archive/zip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/helper"
	"github.com/max-zit/controlzit/internal/logfile"
	"github.com/max-zit/controlzit/internal/store"
)

// Settings → Diagnostics: where the logs are, their newest lines, and a
// zip for support. Nothing that leaves through this page may help an
// attacker: everything passes redact (passwords, tokens, enrollment codes,
// keys, the database password), scripts and their output are not
// included, and the zip has no secrets of the settings.

// HelperLog is the root helper's log (only root writes it).
const HelperLog = "/var/log/controlzit-helper/helper.log"

const diagLogMax = 20 << 20

var redactions = []struct {
	re   *regexp.Regexp
	with string
}{
	// PEM blocks (keys, certificates)
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----`), "-----(PEM block removed)-----"},
	// URLs with a password: scheme://user:secret@host
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:)[^\s@/]+@`), "${1}***@"},
	// Authorization: Bearer xxx
	{regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}`), "${1}***"},
	// key=value, "key": "value" and \"key\":\"value\" (JSON inside a log
	// line) for words that name a secret
	{regexp.MustCompile(`(?i)((?:password|passwd|pass|pwd|secret|token|apikey|api_key|authorization|cookie)[\\"']*\s*[:=]\s*[\\"']*)[^\s"'\\,&;]+`), "${1}***"},
	// ControlZit enrollment codes
	{regexp.MustCompile(`CZ1-[A-Za-z0-9_=-]{10,}`), "CZ1-***"},
}

var longToken = regexp.MustCompile(`[A-Za-z0-9+_=]{32,}`)

// redact removes secrets from text.
func redact(s string) string {
	for _, r := range redactions {
		s = r.re.ReplaceAllString(s, r.with)
	}
	// Long runs of letters and digits without separators: keys and tokens.
	s = longToken.ReplaceAllStringFunc(s, func(t string) string {
		digits, letters := 0, 0
		for _, c := range t {
			switch {
			case c >= '0' && c <= '9':
				digits++
			case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
				letters++
			}
		}
		if digits >= 4 && letters >= 4 {
			return "***"
		}
		return t
	})
	return s
}

type diagLogLine struct {
	Text  string
	Level string // info, warn, error
}

type diagData struct {
	ServerLog string
	HelperLog string
	DataDir   string
	Lines     []diagLogLine
	HelperLns []diagLogLine
	Level     string
	Q         string
	Version   string
	HelperOK  bool
	DBInfo    string
	GoVersion string
	OS        string
}

func logLines(b []byte, level, q string, max int) []diagLogLine {
	var out []diagLogLine
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if l == "" {
			continue
		}
		lv := "info"
		switch {
		case strings.Contains(l, "level=ERROR"):
			lv = "error"
		case strings.Contains(l, "level=WARN"):
			lv = "warn"
		}
		if (level == "warn" && lv == "info") || (level == "error" && lv != "error") {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(l), strings.ToLower(q)) {
			continue
		}
		out = append(out, diagLogLine{Text: redact(l), Level: lv})
	}
	if len(out) > max {
		out = out[len(out)-max:]
	}
	return out
}

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	d := &diagData{ServerLog: s.LogFile, HelperLog: HelperLog, DataDir: s.DataDir, Level: r.FormValue("level"), Q: strings.TrimSpace(r.FormValue("q")),
		Version: s.Version, HelperOK: s.helperOK(), GoVersion: runtime.Version(), OS: runtime.GOOS + "/" + runtime.GOARCH}
	if len(d.Q) > 100 {
		d.Q = d.Q[:100]
	}
	if s.LogFile != "" {
		if b, err := logfile.Tail(s.LogFile, 1, 512<<10); err == nil {
			d.Lines = logLines(b, d.Level, d.Q, 300)
		}
	}
	if b, err := logfile.Tail(HelperLog, 0, 64<<10); err == nil {
		d.HelperLns = logLines(b, "", "", 40)
	}
	d.DBInfo = s.store.DBInfo(r.Context())
	s.render(w, r, http.StatusOK, "diagnostics", &Page{Title: "Diagnostics", Nav: "settings", Data: d})
}

// handleDiagnosticsZip sends the diagnostics for support.
func (s *Server) handleDiagnosticsZip(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := s.now()
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="controlzit-diagnostics-`+now.Format("20060102-1504")+`.zip"`)
	w.Header().Set("Cache-Control", "no-store")
	z := zip.NewWriter(w)
	add := func(name string, write func(io.Writer) error) {
		f, err := z.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: now})
		if err != nil {
			return
		}
		if err := write(f); err != nil {
			fmt.Fprintf(f, "\n(error: %v)\n", err)
		}
	}
	add("README.txt", func(w io.Writer) error {
		_, err := io.WriteString(w, "ControlZit diagnostics. Passwords, tokens, enrollment codes and keys are removed;\r\nscripts and their output are not included.\r\n")
		return err
	})
	add("info.txt", func(w io.Writer) error { return s.diagInfo(ctx, w, now) })
	if s.LogFile != "" {
		add("server.log", func(w io.Writer) error {
			b, err := logfile.Tail(s.LogFile, logfile.DefaultKeep, diagLogMax)
			_, _ = io.WriteString(w, redact(string(b)))
			return err
		})
	}
	add("helper.log", func(w io.Writer) error {
		b, err := logfile.Tail(HelperLog, logfile.DefaultKeep, 2<<20)
		_, _ = io.WriteString(w, redact(string(b)))
		return err
	})
	add("devices.csv", func(w io.Writer) error { return s.diagDevices(ctx, w) })
	add("alerts.csv", func(w io.Writer) error { return s.diagAlerts(ctx, w) })
	add("audit.csv", func(w io.Writer) error { return s.diagAudit(ctx, w) })
	_ = z.Close()
	s.audit(r, "diagnostics.download", "settings", "diagnostics zip downloaded")
}

func (s *Server) diagInfo(ctx context.Context, w io.Writer, now time.Time) error {
	host, _ := os.Hostname()
	fmt.Fprintf(w, "ControlZit server %s\r\nCreated: %s\r\nHost: %s (%s/%s, %s)\r\nTime zone: %s\r\nDatabase: %s\r\n",
		s.Version, now.Format(time.RFC3339), host, runtime.GOOS, runtime.GOARCH, runtime.Version(), now.Format("MST -07:00"), s.store.DBInfo(ctx))
	fmt.Fprintf(w, "Console: %s (running), agents: %s (running)\r\nRoot helper: %v\r\nAppliance: %v\r\n", s.RunningMgmt, s.RunningAgent, s.helperOK(), helper.IsAppliance(""))
	n, _ := s.Network(ctx)
	fmt.Fprintf(w, "Allowed console networks: %s\r\nAllowed agent networks: %s\r\nPublic agent address: %s\r\n",
		strings.Join(n.MgmtAllowed, " "), strings.Join(n.AgentAllowed, " "), n.PublicAgentURL)
	c := s.Cert(ctx)
	fmt.Fprintf(w, "Certificate: %s %s (port 80: %v)\r\n", c.Mode, c.Hostname, c.HTTP80)
	if i := s.TLS.Info(); i != nil {
		fmt.Fprintf(w, "Certificate in use: %s, issued by %s, expires %s\r\n", strings.Join(i.Names, ", "), i.Issuer, i.NotAfter.Format("2006-01-02"))
	}
	e := s.Email(ctx)
	fmt.Fprintf(w, "Email: %v (server %s:%d)\r\n", e.Configured(), e.Host, e.Port)
	if res := s.lastHelperResult(); res != nil {
		fmt.Fprintf(w, "Last helper request: %s %s at %s: %s\r\n", res.Action, res.Status, res.Started.Format(time.RFC3339), redact(res.Message))
	}
	return nil
}

func (s *Server) diagDevices(ctx context.Context, w io.Writer) error {
	all := &store.User{Role: store.RoleAdmin}
	list, err := s.store.Devices(ctx, all, store.DeviceFilter{})
	if err != nil {
		return err
	}
	c := csv.NewWriter(w)
	_ = c.Write([]string{"id", "customer", "site", "hostname", "os", "agent", "online", "last_seen", "enrolled"})
	for _, d := range list {
		_ = c.Write([]string{strconv.FormatInt(d.ID, 10), d.Customer, d.Site, d.Hostname, d.OS, d.AgentVersion, strconv.FormatBool(s.Connected(d.ID)),
			fmtTime(d.LastSeenAt), d.EnrolledAt.Format(time.RFC3339)})
	}
	c.Flush()
	return c.Error()
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

func (s *Server) diagAlerts(ctx context.Context, w io.Writer) error {
	all := &store.User{Role: store.RoleAdmin}
	list, err := s.store.Alerts(ctx, all, store.AlertFilter{Limit: 1000})
	if err != nil {
		return err
	}
	c := csv.NewWriter(w)
	_ = c.Write([]string{"id", "device", "kind", "opened", "resolved", "message"})
	for _, a := range list {
		_ = c.Write([]string{strconv.FormatInt(a.ID, 10), a.Hostname, a.Kind, a.OpenedAt.Format(time.RFC3339), fmtTime(a.ResolvedAt), redact(a.Message)})
	}
	c.Flush()
	return c.Error()
}

// diagAudit exports the audit log without script bodies and output.
func (s *Server) diagAudit(ctx context.Context, w io.Writer) error {
	list, err := s.store.AuditEntries(ctx, store.AuditFilter{Limit: 2000})
	if err != nil {
		return err
	}
	c := csv.NewWriter(w)
	_ = c.Write([]string{"id", "time", "user", "action", "target", "detail", "address"})
	for _, e := range list {
		detail := e.Detail
		if i := strings.Index(detail, " --- script ---"); i >= 0 {
			detail = detail[:i] + " (script not included)"
		}
		_ = c.Write([]string{strconv.FormatInt(e.ID, 10), e.At.Format(time.RFC3339), e.Username, e.Action, e.Target, redact(detail), e.IP})
	}
	c.Flush()
	return c.Error()
}
