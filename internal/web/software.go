package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/store"
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
	// Chocolatey (when switched on) and the software library.
	Choco       bool
	Source      string // winget or choco (search)
	ChocoResult *proto.WingetResult
	ChocoErr    string
	Library     []store.SoftwarePackage
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
	sd := &softwareData{D: d, View: r.FormValue("view"), Query: strings.TrimSpace(r.FormValue("q")), Choco: s.softwareSettings(r.Context()).Chocolatey, Source: "winget"}
	if sd.Choco && r.FormValue("source") == "choco" {
		sd.Source = "choco"
	}
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
	} else if sd.View == "search" && sd.Source == "choco" {
		if sd.Query != "" {
			sd.Result, sd.Err, sd.Offline = s.chocoCall(r, d, proto.Choco{Action: proto.ChocoSearch, Query: sd.Query}, 4*time.Minute)
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
	if sd.View == "upgrades" && sd.Choco && !sd.Offline {
		sd.ChocoResult, sd.ChocoErr, _ = s.chocoCall(r, d, proto.Choco{Action: proto.ChocoOutdated}, 4*time.Minute)
	}
	if sd.View == "search" {
		lib, err := s.store.SoftwarePackages(r.Context())
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		sd.Library = lib
	}
	s.render(w, r, http.StatusOK, "software", &Page{Title: d.Hostname, Nav: "devices", Data: sd})
}

func (s *Server) handleSoftwareAction(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	a := proto.Winget{Action: r.FormValue("action"), ID: strings.TrimSpace(r.FormValue("id"))}
	back := s.deviceURL(d, "/software?view="+url.QueryEscape(r.FormValue("view"))+"&q="+url.QueryEscape(r.FormValue("q"))+"&source="+url.QueryEscape(r.FormValue("source")))
	if a.Action == "remove" {
		s.removeProgram(w, r, d, r.FormValue("key"), back)
		return
	}
	switch a.Action {
	case "library":
		s.installFromLibrary(w, r, d, back)
		return
	case "choco-install", "choco-upgrade":
		s.chocoAction(w, r, d, strings.TrimPrefix(a.Action, "choco-"), a.ID, back)
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
	title := map[string]string{proto.WingetInstall: "Install %s (winget)", proto.WingetUpgrade: "Update %s (winget)", proto.WingetUninstall: "Uninstall %s (winget)"}[a.Action]
	var args []string
	if a.ID == proto.WingetAll {
		title = "Update all programs (winget)"
	} else {
		args = []string{a.ID}
	}
	s.startTask(w, r, d, "winget", title, args, wingetTask{Winget: a, Back: back})
}

// removeProgram uninstalls an installed program silently; the agent reports
// success only when its uninstall entry is gone.
func (s *Server) removeProgram(w http.ResponseWriter, r *http.Request, d *store.Device, key, back string) {
	if !proto.ValidProgramKey(key) {
		s.redirect(w, r, back, "Unknown action.")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = key
	}
	s.startTask(w, r, d, "uninstall", "Uninstall %s", []string{name}, uninstallTask{Key: key, Name: name, Back: back})
}

// chocoCall runs a Chocolatey list action; it returns the error as text.
func (s *Server) chocoCall(r *http.Request, d *store.Device, a proto.Choco, limit time.Duration) (*proto.WingetResult, string, bool) {
	var res proto.WingetResult
	if err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindChoco, a, &res, limit); err != nil {
		return nil, translate(s.lang(r, userFrom(r)), err.Error()), errors.Is(err, ErrOffline)
	}
	return &res, "", false
}

// chocoAction installs or updates a Chocolatey package (or all of them).
func (s *Server) chocoAction(w http.ResponseWriter, r *http.Request, d *store.Device, action, id, back string) {
	if !s.softwareSettings(r.Context()).Chocolatey {
		s.redirect(w, r, back, "Chocolatey is off.")
		return
	}
	if !proto.ValidChocoID(id) && !(action == proto.ChocoUpgrade && id == proto.WingetAll) {
		s.redirect(w, r, back, "Unknown action.")
		return
	}
	title, args := "Install %s (Chocolatey)", []string{id}
	switch {
	case id == proto.WingetAll:
		title, args = "Update all Chocolatey packages", nil
	case action == proto.ChocoUpgrade:
		title = "Update %s (Chocolatey)"
	}
	s.startTask(w, r, d, "choco", title, args, chocoTask{Choco: proto.Choco{Action: action, ID: id}, Back: back})
}

// installFromLibrary starts a job that installs a library package on this
// device and shows the job.
func (s *Server) installFromLibrary(w http.ResponseWriter, r *http.Request, d *store.Device, back string) {
	id, err := strconv.ParseInt(r.FormValue("package"), 10, 64)
	if err != nil || !d.IsWindows() {
		s.redirect(w, r, back, "Unknown action.")
		return
	}
	p, err := s.store.SoftwarePackage(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.redirect(w, r, back, "Unknown action.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	j, err := s.packageJob(r.Context(), s.issuer(r), p, []int64{d.ID})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "job.create", "job:"+strconv.FormatInt(j.ID, 10), "install software package %q %s on %q", p.Name, p.Version, d.Hostname)
	go s.DispatchJobs(context.Background()) // #nosec G118 -- the job runs after the page has answered
	s.redirect(w, r, "/jobs/"+strconv.FormatInt(j.ID, 10), "")
}
