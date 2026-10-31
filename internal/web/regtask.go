package web

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/store"
	"github.com/max-zit/rmmzit/internal/update"
)

// Registry editor and scheduled tasks of Windows devices (agents
// regTaskVersion and newer). Every change is audited, a registry change
// with the value it replaced.

const regTaskVersion = "0.12.0"

// tooOldFor reports a device whose agent lacks a feature of version v.
// A development build ("dev") counts as the newest.
func tooOldFor(d *store.Device, v string) bool {
	return d.AgentVersion != "dev" && update.Newer(v, d.AgentVersion)
}

type regCrumb struct{ Name, Path string }

type registryData struct {
	D         *store.Device
	Path      string
	Crumbs    []regCrumb
	Key       *proto.RegKey
	Roots     []string
	Types     []string
	Protected bool
	Err       string
	Offline   bool
	OldAgent  bool
}

// SubPath joins the shown key with a subkey (for the links).
func (d *registryData) SubPath(name string) string { return d.Path + `\` + name }

// Editable reports whether the editor writes values of type t.
func (d *registryData) Editable(t string) bool { return slices.Contains(proto.RegValueTypes, t) }

func (s *Server) handleRegistry(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	rd := &registryData{D: d, Roots: proto.RegRoots, Types: proto.RegValueTypes, OldAgent: tooOldFor(d, regTaskVersion)}
	if p := strings.TrimSpace(r.FormValue("path")); p != "" && !rd.OldAgent {
		path, err := proto.CleanRegPath(p)
		if err != nil {
			rd.Err = translate(s.lang(r, userFrom(r)), err.Error())
		} else {
			rd.Path = path
			parts := strings.Split(path, `\`)
			for i := range parts {
				rd.Crumbs = append(rd.Crumbs, regCrumb{parts[i], strings.Join(parts[:i+1], `\`)})
			}
			rd.Protected = proto.ProtectedRegKey(path)
			var key proto.RegKey
			if err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindRegList, proto.RegPath{Path: path}, &key, actionTimeout); err != nil {
				rd.Offline = errors.Is(err, ErrOffline)
				rd.Err = translate(s.lang(r, userFrom(r)), err.Error())
			} else {
				rd.Key = &key
			}
		}
	}
	s.render(w, r, http.StatusOK, "registry", &Page{Title: d.Hostname, Nav: "devices", Data: rd})
}

func (s *Server) handleRegistryChange(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	path, err := proto.CleanRegPath(r.FormValue("path"))
	back := s.deviceURL(d, "/registry?path="+url.QueryEscape(path))
	if err != nil || tooOldFor(d, regTaskVersion) {
		s.redirectErr(w, r, s.deviceURL(d, "/registry"), uiErr("Unknown action."))
		return
	}
	name := r.FormValue("name")
	ctx, issuer := r.Context(), s.issuer(r)
	switch r.FormValue("action") {
	case "set":
		v := proto.RegValue{Name: name, Type: r.FormValue("type"), Data: r.FormValue("data")}
		var res struct {
			Old *proto.RegValue `json:"old"`
		}
		if err := s.call(ctx, d.ID, issuer, proto.KindRegSet, proto.RegSet{Path: path, RegValue: v}, &res, actionTimeout); err != nil {
			s.redirectErr(w, r, back, err)
			return
		}
		old := "(new)"
		if res.Old != nil {
			old = res.Old.Type + " " + clip(res.Old.Data, 500)
		}
		s.audit(r, "registry.set", deviceTarget(d), "%s\\%s on %q: %s → %s %s", path, regName(name), d.Hostname, old, v.Type, clip(v.Data, 500))
		s.redirect(w, r, back, "Saved.")
	case "delete":
		if err := s.call(ctx, d.ID, issuer, proto.KindRegDelete, proto.RegDelete{Path: path, Name: name}, nil, actionTimeout); err != nil {
			s.redirectErr(w, r, back, err)
			return
		}
		s.audit(r, "registry.delete", deviceTarget(d), "deleted the value %s\\%s on %q", path, regName(name), d.Hostname)
		s.redirect(w, r, back, "Deleted.")
	case "newkey":
		if err := s.call(ctx, d.ID, issuer, proto.KindRegNewKey, proto.RegNewKey{Path: path, Name: strings.TrimSpace(name)}, nil, actionTimeout); err != nil {
			s.redirectErr(w, r, back, err)
			return
		}
		s.audit(r, "registry.newkey", deviceTarget(d), "created the key %s\\%s on %q", path, strings.TrimSpace(name), d.Hostname)
		s.redirect(w, r, s.deviceURL(d, "/registry?path="+url.QueryEscape(path+`\`+strings.TrimSpace(name))), "Saved.")
	case "deletekey":
		if err := s.call(ctx, d.ID, issuer, proto.KindRegDelete, proto.RegDelete{Path: path, Key: true}, nil, actionTimeout+time.Minute); err != nil {
			s.redirectErr(w, r, back, err)
			return
		}
		s.audit(r, "registry.deletekey", deviceTarget(d), "deleted the key %s with all it held on %q", path, d.Hostname)
		s.redirect(w, r, s.deviceURL(d, "/registry?path="+url.QueryEscape(path[:strings.LastIndex(path, `\`)])), "Deleted.")
	default:
		s.redirectErr(w, r, back, uiErr("Unknown action."))
	}
}

func regName(n string) string {
	if n == "" {
		return "(default)"
	}
	return n
}

// ---- scheduled tasks

type tasksData struct {
	D        *store.Device
	Tasks    []proto.SchedTask
	All      bool
	Q        string
	Total    int
	Err      string
	Offline  bool
	OldAgent bool
}

func (s *Server) handleSchedTasks(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	td := &tasksData{D: d, All: r.FormValue("all") == "1", Q: strings.TrimSpace(r.FormValue("q")), OldAgent: tooOldFor(d, regTaskVersion)}
	if !td.OldAgent {
		var list []proto.SchedTask
		if err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindTaskList, proto.TaskList{All: td.All}, &list, 4*time.Minute); err != nil {
			td.Offline = errors.Is(err, ErrOffline)
			td.Err = translate(s.lang(r, userFrom(r)), err.Error())
		}
		td.Total = len(list)
		q := strings.ToLower(td.Q)
		for _, t := range list {
			if q == "" || strings.Contains(strings.ToLower(t.Path+t.Name+" "+t.Action), q) {
				td.Tasks = append(td.Tasks, t)
			}
		}
	}
	s.render(w, r, http.StatusOK, "schedtasks", &Page{Title: d.Hostname, Nav: "devices", Data: td})
}

func (s *Server) handleSchedTaskControl(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	a := proto.TaskControl{Path: r.FormValue("path"), Name: r.FormValue("name"), Action: r.FormValue("action")}
	back := s.deviceURL(d, "/tasks?q="+url.QueryEscape(r.FormValue("q"))+"&all="+url.QueryEscape(r.FormValue("all")))
	if proto.ValidTaskControl(a) != nil || tooOldFor(d, regTaskVersion) {
		s.redirectErr(w, r, back, uiErr("Unknown action."))
		return
	}
	err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindTaskCtl, a, nil, 2*time.Minute)
	if err != nil {
		s.audit(r, "schedtask."+a.Action, deviceTarget(d), "%s of the scheduled task %s%s on %q failed: %v", a.Action, a.Path, a.Name, d.Hostname, err)
		s.redirectErr(w, r, back, err)
		return
	}
	s.audit(r, "schedtask."+a.Action, deviceTarget(d), "%s of the scheduled task %s%s on %q", a.Action, a.Path, a.Name, d.Hostname)
	msg := map[string]string{"run": "Task %s started.", "end": "Task %s ended.", "enable": "Task %s enabled.", "disable": "Task %s disabled.", "delete": "Task %s deleted."}[a.Action]
	s.redirect(w, r, back, translate(s.lang(r, userFrom(r)), msg, a.Name))
}

// TaskResult writes a task's last result the way Windows shows it.
func (d *tasksData) TaskResult(code int64) string {
	switch code {
	case 0:
		return "0 (OK)"
	case 0x41301:
		return "0x41301 (running)"
	case 0x41303:
		return "0x41303 (not run yet)"
	}
	return "0x" + strings.ToUpper(strconv.FormatUint(uint64(uint32(code)), 16)) // #nosec G115 -- a 32-bit HRESULT, shown as Windows does
}
