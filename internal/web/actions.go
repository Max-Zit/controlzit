package web

import (
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

// Remote actions: services, processes, scripts and power. Like the file
// manager they need the technician role, go to the agent as signed
// commands and are written to the audit log.

const (
	actionTimeout = 90 * time.Second
	// maxScriptTimeout keeps a script inside the lifetime of one command.
	maxScriptTimeout = 1500
	// auditScript and auditOutput limit what the audit entry of a script
	// keeps; the full output is in the run history.
	auditScript = 4 << 10
	auditOutput = 8 << 10
)

func deviceTarget(d *store.Device) string { return "device:" + strconv.FormatInt(d.ID, 10) }

func (s *Server) deviceURL(d *store.Device, sub string) string {
	return "/devices/" + strconv.FormatInt(d.ID, 10) + sub
}

// ---- services

type servicesData struct {
	D        *store.Device
	Services []proto.Service
	Q, State string
	Total    int
	Err      string
	Offline  bool
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	sd := &servicesData{D: d, Q: strings.TrimSpace(r.FormValue("q")), State: r.FormValue("state")}
	var list []proto.Service
	err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindSvcList, nil, &list, actionTimeout)
	if err != nil {
		sd.Offline = errors.Is(err, ErrOffline)
		sd.Err = translate(s.lang(r, userFrom(r)), err.Error())
	}
	sd.Total = len(list)
	q := strings.ToLower(sd.Q)
	for _, v := range list {
		if q != "" && !strings.Contains(strings.ToLower(v.Name), q) && !strings.Contains(strings.ToLower(v.Display), q) {
			continue
		}
		switch sd.State {
		case "running":
			if v.State != "running" {
				continue
			}
		case "stopped":
			if v.State != "stopped" {
				continue
			}
		case "auto-stopped":
			if v.State == "running" || !strings.HasPrefix(v.StartType, "automatic") {
				continue
			}
		}
		sd.Services = append(sd.Services, v)
	}
	s.render(w, r, http.StatusOK, "services", &Page{Title: d.Hostname, Nav: "devices", Data: sd})
}

func (s *Server) handleServiceControl(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	a := proto.SvcControl{Name: strings.TrimSpace(r.FormValue("name")), Action: r.FormValue("action")}
	back := s.deviceURL(d, "/services?q="+url.QueryEscape(r.FormValue("q"))+"&state="+url.QueryEscape(r.FormValue("state")))
	if a.Name == "" || (a.Action != "start" && a.Action != "stop" && a.Action != "restart") {
		s.redirect(w, r, back, "Unknown action.")
		return
	}
	err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindSvcCtl, a, nil, actionTimeout+60*time.Second)
	if err != nil {
		s.audit(r, "service."+a.Action, deviceTarget(d), "%s of service %s on %q failed: %v", a.Action, a.Name, d.Hostname, err)
		s.redirect(w, r, back, err.Error())
		return
	}
	s.audit(r, "service."+a.Action, deviceTarget(d), "%s of service %s on %q", a.Action, a.Name, d.Hostname)
	msg := map[string]string{"start": "Service %s started.", "stop": "Service %s stopped.", "restart": "Service %s restarted."}[a.Action]
	s.redirect(w, r, back, translate(s.lang(r, userFrom(r)), msg, a.Name))
}

// ---- processes

type processesData struct {
	D         *store.Device
	Processes []proto.Process
	Q, Sort   string
	Total     int
	Err       string
	Offline   bool
}

func (s *Server) handleProcesses(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	pd := &processesData{D: d, Q: strings.TrimSpace(r.FormValue("q")), Sort: r.FormValue("sort")}
	var list []proto.Process
	err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindProcList, nil, &list, actionTimeout)
	if err != nil {
		pd.Offline = errors.Is(err, ErrOffline)
		pd.Err = translate(s.lang(r, userFrom(r)), err.Error())
	}
	pd.Total = len(list)
	q := strings.ToLower(pd.Q)
	for _, p := range list {
		if q != "" && !strings.Contains(strings.ToLower(p.Name), q) && strconv.FormatUint(uint64(p.PID), 10) != q {
			continue
		}
		pd.Processes = append(pd.Processes, p)
	}
	switch pd.Sort {
	case "name":
		sort.SliceStable(pd.Processes, func(i, j int) bool {
			return strings.ToLower(pd.Processes[i].Name) < strings.ToLower(pd.Processes[j].Name)
		})
	case "pid":
		sort.SliceStable(pd.Processes, func(i, j int) bool { return pd.Processes[i].PID < pd.Processes[j].PID })
	default:
		pd.Sort = "mem" // the agent sends them by memory
	}
	s.render(w, r, http.StatusOK, "processes", &Page{Title: d.Hostname, Nav: "devices", Data: pd})
}

func (s *Server) handleProcessKill(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	back := s.deviceURL(d, "/processes?q="+url.QueryEscape(r.FormValue("q"))+"&sort="+url.QueryEscape(r.FormValue("sort")))
	pid, err := strconv.ParseUint(r.FormValue("pid"), 10, 32)
	name := strings.TrimSpace(r.FormValue("name"))
	if err != nil || name == "" {
		s.redirect(w, r, back, "Unknown process.")
		return
	}
	a := proto.ProcKill{PID: uint32(pid), Name: name}
	if err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindProcKill, a, nil, actionTimeout); err != nil {
		s.audit(r, "process.kill", deviceTarget(d), "ending %s (PID %d) on %q failed: %v", name, pid, d.Hostname, err)
		s.redirect(w, r, back, err.Error())
		return
	}
	s.audit(r, "process.kill", deviceTarget(d), "ended %s (PID %d) on %q", name, pid, d.Hostname)
	s.redirect(w, r, back, translate(s.lang(r, userFrom(r)), "Process %s ended.", name))
}

// ---- scripts

type scriptsData struct {
	D       *store.Device
	Online  bool
	Runs    []store.ScriptRun
	Run     *store.ScriptRun // the run shown
	Shell   string
	Script  string
	Timeout int
}

func (s *Server) handleScripts(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	sd := &scriptsData{D: d, Online: s.Connected(d.ID), Shell: "powershell", Timeout: 300}
	if rid, ok := pathID(r, "rid"); ok {
		run, err := s.store.ScriptRun(r.Context(), d.ID, rid)
		if errors.Is(err, store.ErrNotFound) {
			s.notFound(w, r)
			return
		}
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		sd.Run, sd.Shell, sd.Script = run, run.Shell, run.Script
	}
	runs, err := s.store.ScriptRuns(r.Context(), d.ID, 20)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	sd.Runs = runs
	s.render(w, r, http.StatusOK, "scripts", &Page{Title: d.Hostname, Nav: "devices", Data: sd})
}

func (s *Server) handleScriptRun(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	a := proto.ScriptRun{Shell: r.FormValue("shell"), Script: strings.ReplaceAll(r.FormValue("script"), "\r\n", "\n")}
	a.Timeout, _ = strconv.Atoi(r.FormValue("timeout"))
	back := s.deviceURL(d, "/scripts")
	switch {
	case a.Shell != "powershell" && a.Shell != "cmd":
		s.redirect(w, r, back, "Unknown shell.")
		return
	case strings.TrimSpace(a.Script) == "" || len(a.Script) > proto.MaxScriptSize:
		s.redirect(w, r, back, "The script is empty or longer than 256 KB.")
		return
	case a.Timeout < 5 || a.Timeout > maxScriptTimeout:
		s.redirect(w, r, back, "The time limit must be 5–1500 seconds.")
		return
	}
	// The page waits for the script; lift the server's write timeout.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	run := &store.ScriptRun{DeviceID: d.ID, Username: s.issuer(r), Shell: a.Shell, Script: a.Script, StartedAt: s.now()}
	var res proto.ScriptResult
	err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindScriptRun, a, &res, time.Duration(a.Timeout)*time.Second+actionTimeout)
	if err != nil {
		run.Error = err.Error()
		run.Duration = s.now().Sub(run.StartedAt)
	} else {
		code := res.ExitCode
		run.ExitCode, run.TimedOut, run.Truncated, run.Output, run.Duration = &code, res.TimedOut, res.Truncated, res.Output, res.Duration
	}
	if err := s.store.AddScriptRun(r.Context(), run); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "script.run", deviceTarget(d), "%s", scriptAudit(d, run))
	s.redirect(w, r, s.deviceURL(d, "/scripts/"+strconv.FormatInt(run.ID, 10)), "")
}

// scriptAudit is the audit entry of a run: outcome, script and output.
func scriptAudit(d *store.Device, run *store.ScriptRun) string {
	var b strings.Builder
	b.WriteString("ran " + run.Shell + " script #" + strconv.FormatInt(run.ID, 10) + " on \"" + d.Hostname + "\": ")
	switch {
	case run.Error != "":
		b.WriteString("failed: " + run.Error)
	case run.TimedOut:
		b.WriteString("stopped after the time limit")
	default:
		b.WriteString("exit code " + strconv.Itoa(*run.ExitCode))
	}
	b.WriteString(" (" + run.Duration.Round(time.Millisecond).String() + ")")
	b.WriteString("\n--- script ---\n" + clip(run.Script, auditScript))
	if run.Error == "" {
		b.WriteString("\n--- output ---\n" + clip(run.Output, auditOutput))
	}
	return b.String()
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8Start(s[n]) {
		n--
	}
	return s[:n] + "\n… (" + strconv.Itoa(len(s)) + " bytes in total)"
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// ---- power

func (s *Server) handlePower(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	a := proto.Power{Action: r.FormValue("action"), Message: strings.TrimSpace(r.FormValue("message"))}
	a.Delay, _ = strconv.Atoi(r.FormValue("delay"))
	back := s.deviceURL(d, "")
	if (a.Action != "restart" && a.Action != "shutdown" && a.Action != "cancel") || a.Delay < 0 || a.Delay > 3600 || len(a.Message) > 500 {
		s.redirect(w, r, back, "Unknown action.")
		return
	}
	if a.Action == "cancel" {
		a.Delay, a.Message = 0, ""
	}
	if err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindPower, a, nil, actionTimeout); err != nil {
		s.audit(r, "power."+a.Action, deviceTarget(d), "%s of %q failed: %v", a.Action, d.Hostname, err)
		s.redirect(w, r, back, err.Error())
		return
	}
	s.audit(r, "power."+a.Action, deviceTarget(d), "%s of %q (in %d s)", a.Action, d.Hostname, a.Delay)
	lang := s.lang(r, userFrom(r))
	switch a.Action {
	case "restart":
		s.redirect(w, r, back, translate(lang, "The computer restarts in %d seconds.", a.Delay))
	case "shutdown":
		s.redirect(w, r, back, translate(lang, "The computer shuts down in %d seconds.", a.Delay))
	default:
		s.redirect(w, r, back, "The scheduled restart or shutdown was cancelled.")
	}
}
