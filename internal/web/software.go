package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

// Software with winget: available upgrades, installed packages, search and
// install, upgrade and uninstall (technician role, audited).

type softwareData struct {
	D        *store.Device
	View     string // upgrades, list, search
	Query    string
	Result   *proto.WingetResult
	Programs *proto.ProgramsResult // installed (the registry, not only what winget knows)
	Err      string
	Offline  bool
}

// Shown reports whether the installed program matches the filter.
func (sd *softwareData) Shown(p proto.Program) bool {
	q := strings.ToLower(sd.Query)
	return q == "" || strings.Contains(strings.ToLower(p.Name), q) || strings.Contains(strings.ToLower(p.Publisher), q)
}

func (s *Server) handleSoftware(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	sd := &softwareData{D: d, View: r.FormValue("view"), Query: strings.TrimSpace(r.FormValue("q"))}
	a := proto.Winget{Action: proto.WingetUpgrades}
	switch sd.View {
	case "list":
		a.Action = proto.WingetList
	case "search":
		a.Action, a.Query = proto.WingetSearch, sd.Query
	default:
		sd.View = "upgrades"
	}
	if sd.View == "list" {
		var res proto.ProgramsResult
		err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindPrograms, struct{}{}, &res, time.Minute)
		if err != nil {
			sd.Offline = errors.Is(err, ErrOffline)
			sd.Err = translate(s.lang(r, userFrom(r)), err.Error())
		} else {
			sd.Programs = &res
		}
	} else if sd.View != "search" || sd.Query != "" {
		var res proto.WingetResult
		err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindWinget, a, &res, 4*time.Minute)
		if err != nil {
			sd.Offline = errors.Is(err, ErrOffline)
			sd.Err = translate(s.lang(r, userFrom(r)), err.Error())
		} else {
			sd.Result = &res
		}
	}
	s.render(w, r, http.StatusOK, "software", &Page{Title: d.Hostname, Nav: "devices", Data: sd})
}

func (s *Server) handleSoftwareAction(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	a := proto.Winget{Action: r.FormValue("action"), ID: strings.TrimSpace(r.FormValue("id"))}
	back := s.deviceURL(d, "/software?view="+url.QueryEscape(r.FormValue("view"))+"&q="+url.QueryEscape(r.FormValue("q")))
	if a.Action == "remove" {
		s.removeProgram(w, r, d, r.FormValue("key"), back)
		return
	}
	switch a.Action {
	case proto.WingetInstall, proto.WingetUninstall, proto.WingetUpgrade:
	default:
		s.redirect(w, r, back, "Unknown action.")
		return
	}
	if !proto.ValidWingetID(a.ID) && !(a.Action == proto.WingetUpgrade && a.ID == proto.WingetAll) {
		s.redirect(w, r, back, "Unknown action.")
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{}) // installers take a while
	var res proto.WingetResult
	err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindWinget, a, &res, 27*time.Minute)
	what := a.ID
	if a.ID == proto.WingetAll {
		what = "all packages"
	}
	if err != nil {
		s.audit(r, "software."+a.Action, deviceTarget(d), "winget %s %s on %q failed: %v", a.Action, what, d.Hostname, err)
		s.redirect(w, r, back, err.Error())
		return
	}
	s.audit(r, "software."+a.Action, deviceTarget(d), "winget %s %s on %q: exit code 0x%X\n%s", a.Action, what, d.Hostname, uint32(res.ExitCode), clip(res.Output, auditOutput)) // #nosec G115 -- exit codes are 32-bit
	lang := s.lang(r, userFrom(r))
	if res.ExitCode != 0 {
		s.redirect(w, r, back, translate(lang, "winget ended with code %s; the audit log has its output.", fmt.Sprintf("0x%X", uint32(res.ExitCode)))) // #nosec G115 -- exit codes are 32-bit
		return
	}
	msg := map[string]string{proto.WingetInstall: "%s installed.", proto.WingetUpgrade: "%s updated.", proto.WingetUninstall: "%s uninstalled."}[a.Action]
	s.redirect(w, r, back, translate(lang, msg, what))
}

// removeProgram uninstalls an installed program silently; the agent reports
// success only when its uninstall entry is gone.
func (s *Server) removeProgram(w http.ResponseWriter, r *http.Request, d *store.Device, key, back string) {
	if !proto.ValidProgramKey(key) {
		s.redirect(w, r, back, "Unknown action.")
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{}) // uninstallers take a while
	name := strings.TrimSpace(r.FormValue("name"))
	var res proto.UninstallResult
	err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindUninstall, proto.Uninstall{Key: key}, &res, 27*time.Minute)
	if err != nil {
		s.audit(r, "software.uninstall", deviceTarget(d), "uninstall %s (%s) on %q failed: %v", clip(name, 200), key, d.Hostname, err)
		s.redirect(w, r, back, err.Error())
		return
	}
	if res.Name != "" {
		name = res.Name
	}
	s.audit(r, "software.uninstall", deviceTarget(d), "uninstalled %s (%s, %s) on %q: exit code %d", name, key, res.Method, d.Hostname, res.ExitCode)
	s.redirect(w, r, back, translate(s.lang(r, userFrom(r)), "%s uninstalled.", name))
}
