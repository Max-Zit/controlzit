package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

// REST API for scripts and other tools, on the console port:
//
//	Authorization: Bearer czt_…
//
// A token acts as its user (the user's customers) with a role no higher than
// the user's. Browser sessions do not work here, so the API needs no CSRF
// protection; every change is audited with the token's name.

type apiFunc func(r *http.Request, u *store.User) (int, any, error)

// apiError is an error with an HTTP status for the client.
type apiError struct {
	code int
	msg  string
}

func (e *apiError) Error() string { return e.msg }

func apiErr(code int, format string, args ...any) error {
	return &apiError{code: code, msg: fmt.Sprintf(format, args...)}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// apiAuth checks the token and the role, then runs h.
func (s *Server) apiAuth(role string, h apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		ip := clientIP(r)
		if until := s.guard.blocked(r.Context(), ip); !until.IsZero() {
			w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(until).Seconds())+1))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed sign-ins from this address"})
			return
		}
		secret, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		u, tok, err := s.store.TokenUser(r.Context(), strings.TrimSpace(secret))
		if err != nil {
			s.guard.fail(r.Context(), ip, "", "API token")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing, invalid or expired API token"})
			return
		}
		if (role == store.RoleAdmin && !u.IsAdmin()) || (role == store.RoleTechnician && !u.CanWrite()) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "the token's role does not allow this"})
			return
		}
		u.Username = u.Username + " (API token " + strconv.Quote(tok.Name) + ")"
		r = r.WithContext(context.WithValue(r.Context(), ctxUser, u))
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		code, v, err := h(r, u)
		if err != nil {
			var ae *apiError
			switch {
			case errors.As(err, &ae):
				writeJSON(w, ae.code, map[string]string{"error": ae.msg})
			case errors.Is(err, store.ErrNotFound):
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			default:
				s.log.Error("api", "path", r.URL.Path, "err", err)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			}
			return
		}
		writeJSON(w, code, v)
	}
}

// apiBody decodes a JSON request body strictly.
func apiBody(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return apiErr(http.StatusBadRequest, "bad JSON: %v", err)
	}
	return nil
}

func apiID(r *http.Request, name string) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || id <= 0 {
		return 0, apiErr(http.StatusBadRequest, "bad %s", name)
	}
	return id, nil
}

// APIHandler serves /api/v1 (mounted on the console listener).
func (s *Server) APIHandler() http.Handler {
	mux := http.NewServeMux()
	read := func(p string, h apiFunc) { mux.HandleFunc(p, s.apiAuth(store.RoleReadOnly, h)) }
	write := func(p string, h apiFunc) { mux.HandleFunc(p, s.apiAuth(store.RoleTechnician, h)) }
	admin := func(p string, h apiFunc) { mux.HandleFunc(p, s.apiAuth(store.RoleAdmin, h)) }

	read("GET /api/v1/me", s.apiMe)
	read("GET /api/v1/customers", s.apiCustomers)
	read("GET /api/v1/customers/{id}/sites", s.apiSites)
	read("GET /api/v1/devices", s.apiDevices)
	read("GET /api/v1/devices/{id}", s.apiDevice)
	read("GET /api/v1/devices/{id}/tasks", s.apiDeviceTasks)
	write("POST /api/v1/devices/{id}/tasks", s.apiTaskCreate)
	write("PUT /api/v1/devices/{id}/fields", s.apiDeviceFields)
	read("GET /api/v1/tasks/{id}", s.apiTask)
	write("POST /api/v1/tasks/{id}/cancel", s.apiTaskCancel)
	read("GET /api/v1/alerts", s.apiAlerts)
	write("GET /api/v1/software", s.apiSoftware)
	write("POST /api/v1/software/{id}/install", s.apiSoftwareInstall)
	write("GET /api/v1/jobs/{id}", s.apiJob)
	admin("GET /api/v1/policies", s.apiPolicies)
	admin("POST /api/v1/policies/{id}/assign", s.apiPolicyAssign)
	admin("POST /api/v1/policies/unassign", s.apiPolicyUnassign)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such API call; see /docs/api"})
	})
	return mux
}

// ---- JSON shapes

type apiDeviceJSON struct {
	ID           int64             `json:"id"`
	Hostname     string            `json:"hostname"`
	CustomerID   int64             `json:"customer_id"`
	Customer     string            `json:"customer"`
	SiteID       int64             `json:"site_id"`
	Site         string            `json:"site"`
	OS           string            `json:"os"`
	OSVersion    string            `json:"os_version,omitempty"`
	AgentVersion string            `json:"agent_version,omitempty"`
	Online       bool              `json:"online"`
	LastSeen     *time.Time        `json:"last_seen,omitempty"`
	CustomFields map[string]string `json:"custom_fields,omitempty"`
}

func (s *Server) deviceJSON(d *store.Device) apiDeviceJSON {
	return apiDeviceJSON{ID: d.ID, Hostname: d.Hostname, CustomerID: d.CustomerID, Customer: d.Customer, SiteID: d.SiteID, Site: d.Site,
		OS: d.OS, OSVersion: d.OSVersion, AgentVersion: d.AgentVersion, Online: s.Connected(d.ID), LastSeen: d.LastSeenAt}
}

type apiTaskJSON struct {
	ID         int64      `json:"id"`
	DeviceID   int64      `json:"device_id"`
	Kind       string     `json:"kind"`
	Title      string     `json:"title"`
	Status     string     `json:"status"` // queued, running, done, failed, cancelled, expired
	Result     string     `json:"result,omitempty"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	JobID      *int64     `json:"job_id,omitempty"`
}

func taskJSON(t *store.DeviceTask) apiTaskJSON {
	return apiTaskJSON{ID: t.ID, DeviceID: t.DeviceID, Kind: t.Kind, Title: taskText("en", t.Title, t.TitleArgs), Status: t.Status,
		Result: taskText("en", t.Result, t.ResultArgs), CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt, StartedAt: t.StartedAt, FinishedAt: t.FinishedAt, JobID: t.JobID}
}

// ---- calls

func (s *Server) apiMe(r *http.Request, u *store.User) (int, any, error) {
	return http.StatusOK, map[string]any{"username": u.Username, "role": u.Role, "all_customers": u.AllCustomers || u.IsAdmin(), "customers": u.CustomerIDs, "version": s.Version}, nil
}

func (s *Server) apiCustomers(r *http.Request, u *store.User) (int, any, error) {
	list, err := s.store.Customers(r.Context(), u)
	if err != nil {
		return 0, nil, err
	}
	out := []map[string]any{}
	for _, c := range list {
		out = append(out, map[string]any{"id": c.ID, "name": c.Name})
	}
	return http.StatusOK, out, nil
}

func (s *Server) apiSites(r *http.Request, u *store.User) (int, any, error) {
	id, err := apiID(r, "id")
	if err != nil {
		return 0, nil, err
	}
	if !u.SeesCustomer(id) {
		return 0, nil, store.ErrNotFound
	}
	list, err := s.store.Sites(r.Context(), id)
	if err != nil {
		return 0, nil, err
	}
	out := []map[string]any{}
	for _, x := range list {
		out = append(out, map[string]any{"id": x.ID, "name": x.Name, "customer_id": x.CustomerID})
	}
	return http.StatusOK, out, nil
}

func (s *Server) apiDevices(r *http.Request, u *store.User) (int, any, error) {
	f := store.DeviceFilter{Query: r.URL.Query().Get("q"), Limit: 2000}
	f.CustomerID, _ = strconv.ParseInt(r.URL.Query().Get("customer"), 10, 64)
	f.SiteID, _ = strconv.ParseInt(r.URL.Query().Get("site"), 10, 64)
	list, err := s.store.Devices(r.Context(), u, f)
	if err != nil {
		return 0, nil, err
	}
	out := []apiDeviceJSON{}
	fields, err := s.store.AllFieldValues(r.Context(), "device")
	if err != nil {
		return 0, nil, err
	}
	for _, d := range list {
		j := s.deviceJSON(d)
		j.CustomFields = fields[d.ID]
		out = append(out, j)
	}
	return http.StatusOK, out, nil
}

// apiDeviceFor loads a device the user may see.
func (s *Server) apiDeviceFor(r *http.Request, u *store.User) (*store.Device, error) {
	id, err := apiID(r, "id")
	if err != nil {
		return nil, err
	}
	d, err := s.store.Device(r.Context(), id)
	if err != nil {
		return nil, err
	}
	if !u.SeesCustomer(d.CustomerID) {
		return nil, store.ErrNotFound
	}
	return d, nil
}

func (s *Server) apiDevice(r *http.Request, u *store.User) (int, any, error) {
	d, err := s.apiDeviceFor(r, u)
	if err != nil {
		return 0, nil, err
	}
	j := s.deviceJSON(d)
	if fields, err := s.store.AllFieldValues(r.Context(), "device"); err == nil {
		j.CustomFields = fields[d.ID]
	}
	return http.StatusOK, map[string]any{"device": j, "inventory": d.Inventory}, nil
}

func (s *Server) apiDeviceTasks(r *http.Request, u *store.User) (int, any, error) {
	d, err := s.apiDeviceFor(r, u)
	if err != nil {
		return 0, nil, err
	}
	list, err := s.store.DeviceTasks(r.Context(), d.ID, 100)
	if err != nil {
		return 0, nil, err
	}
	out := []apiTaskJSON{}
	for i := range list {
		out = append(out, taskJSON(&list[i]))
	}
	return http.StatusOK, out, nil
}

// apiTaskRequest starts a task on a device.
type apiTaskRequest struct {
	Kind    string   `json:"kind"`              // script, patch.scan, patch.install, winget, choco, power, agent.update, bitlocker.keys
	Shell   string   `json:"shell,omitempty"`   // script: powershell, cmd, bash, sh
	Script  string   `json:"script,omitempty"`  // script
	Timeout int      `json:"timeout,omitempty"` // script: seconds (default 300)
	Action  string   `json:"action,omitempty"`  // winget/choco: install, upgrade, uninstall; power: restart, shutdown, cancel
	ID      string   `json:"id,omitempty"`      // winget or Chocolatey package ID
	Updates []string `json:"updates,omitempty"` // patch.install: update IDs (empty: all missing security updates)
	Reboot  bool     `json:"reboot,omitempty"`  // patch.install
	Delay   int      `json:"delay,omitempty"`   // power: seconds
	Message string   `json:"message,omitempty"` // power
}

func (s *Server) apiTaskCreate(r *http.Request, u *store.User) (int, any, error) {
	d, err := s.apiDeviceFor(r, u)
	if err != nil {
		return 0, nil, err
	}
	var q apiTaskRequest
	if err := apiBody(r, &q); err != nil {
		return 0, nil, err
	}
	kind, title, titleArgs, args, err := s.apiTaskArgs(r.Context(), d, q)
	if err != nil {
		return 0, nil, err
	}
	t, err := s.queueTask(r.Context(), d, u.Username, kind, title, titleArgs, args)
	if err != nil {
		return 0, nil, err
	}
	s.audit(r, "task.queue", deviceTarget(d), "%s on %q (task #%d, API)", taskText("en", title, titleArgs), d.Hostname, t.ID)
	return http.StatusAccepted, taskJSON(t), nil
}

func (s *Server) apiTaskArgs(ctx context.Context, d *store.Device, q apiTaskRequest) (string, string, []string, any, error) {
	bad := func(msg string) (string, string, []string, any, error) {
		return "", "", nil, nil, apiErr(http.StatusBadRequest, "%s", msg)
	}
	back := s.deviceURL(d, "/software")
	switch q.Kind {
	case "script":
		if q.Timeout == 0 {
			q.Timeout = 300
		}
		if msg := checkScript(q.Shell, q.Script, q.Timeout); msg != "" {
			return bad(msg)
		}
		return "script", "Run a %s script", []string{shellName(q.Shell)}, scriptTask{Shell: q.Shell, Script: q.Script, Timeout: q.Timeout}, nil
	case "patch.scan":
		return "patch.scan", "Search for updates", nil, struct{}{}, nil
	case "patch.install":
		rep, _, err := s.store.PatchReport(ctx, d.ID)
		if err != nil || rep == nil {
			return bad("the device has not reported Windows updates yet")
		}
		known := map[string]proto.PatchUpdate{}
		for _, x := range rep.Updates {
			known[strings.ToLower(x.ID)] = x
		}
		var ids, titles []string
		if len(q.Updates) == 0 {
			for _, x := range rep.Updates {
				if x.Security() && !x.Upgrade() {
					ids, titles = append(ids, x.ID), append(titles, x.Title)
				}
			}
		}
		for _, id := range q.Updates {
			x, ok := known[strings.ToLower(id)]
			if !ok {
				return bad("update " + id + " is not missing on this device")
			}
			ids, titles = append(ids, x.ID), append(titles, x.Title)
		}
		if len(ids) == 0 || len(ids) > proto.MaxPatchInstall {
			return bad("no updates to install")
		}
		in := proto.PatchInstall{IDs: ids, Reboot: q.Reboot, By: "API"}
		return "patch.install", "Install %s updates", []string{strconv.Itoa(len(ids))}, patchInstallTask{PatchInstall: in, Titles: titles}, nil
	case "winget":
		a := proto.Winget{Action: q.Action, ID: q.ID}
		if (a.Action != proto.WingetInstall && a.Action != proto.WingetUpgrade && a.Action != proto.WingetUninstall) || !proto.ValidWingetID(a.ID) {
			return bad("winget needs action install, upgrade or uninstall and a package id")
		}
		title := map[string]string{proto.WingetInstall: "Install %s (winget)", proto.WingetUpgrade: "Update %s (winget)", proto.WingetUninstall: "Uninstall %s (winget)"}[a.Action]
		return "winget", title, []string{a.ID}, wingetTask{Winget: a, Back: back}, nil
	case "choco":
		if !s.softwareSettings(ctx).Chocolatey {
			return bad("Chocolatey is off")
		}
		if (q.Action != proto.ChocoInstall && q.Action != proto.ChocoUpgrade) || !proto.ValidChocoID(q.ID) {
			return bad("choco needs action install or upgrade and a package id")
		}
		title := "Install %s (Chocolatey)"
		if q.Action == proto.ChocoUpgrade {
			title = "Update %s (Chocolatey)"
		}
		return "choco", title, []string{q.ID}, chocoTask{Choco: proto.Choco{Action: q.Action, ID: q.ID}, Back: back}, nil
	case "power":
		a := proto.Power{Action: q.Action, Delay: q.Delay, Message: q.Message}
		if (a.Action != "restart" && a.Action != "shutdown" && a.Action != "cancel") || a.Delay < 0 || a.Delay > 3600 || len(a.Message) > 500 {
			return bad("power needs action restart, shutdown or cancel and a delay of 0–3600 seconds")
		}
		switch a.Action {
		case "restart":
			return "power", "Restart in %s seconds", []string{strconv.Itoa(a.Delay)}, a, nil
		case "shutdown":
			return "power", "Shut down in %s seconds", []string{strconv.Itoa(a.Delay)}, a, nil
		}
		return "power", "Cancel the scheduled restart or shutdown", nil, proto.Power{Action: "cancel"}, nil
	case "agent.update":
		pkg := s.packageFor(s.devicePlatform(ctx, d))
		if pkg == nil {
			return bad("there is no agent installer with a known version for this device on the server")
		}
		return "agent.update", "Update the agent to %s", []string{pkg.Version}, struct{}{}, nil
	case "bitlocker.keys":
		return "bitlocker.keys", "Read the BitLocker recovery keys", nil, struct{}{}, nil
	}
	return bad("unknown kind; use script, patch.scan, patch.install, winget, choco, power, agent.update or bitlocker.keys")
}

func (s *Server) apiTaskFor(r *http.Request, u *store.User) (*store.DeviceTask, *store.Device, error) {
	id, err := apiID(r, "id")
	if err != nil {
		return nil, nil, err
	}
	t, err := s.store.Task(r.Context(), id)
	if err != nil {
		return nil, nil, err
	}
	d, err := s.store.Device(r.Context(), t.DeviceID)
	if err != nil || !u.SeesCustomer(d.CustomerID) {
		return nil, nil, store.ErrNotFound
	}
	return t, d, nil
}

func (s *Server) apiTask(r *http.Request, u *store.User) (int, any, error) {
	t, _, err := s.apiTaskFor(r, u)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, taskJSON(t), nil
}

func (s *Server) apiTaskCancel(r *http.Request, u *store.User) (int, any, error) {
	t, d, err := s.apiTaskFor(r, u)
	if err != nil {
		return 0, nil, err
	}
	if done, err := s.store.CancelQueuedTask(r.Context(), t.ID, u.Username); err != nil {
		return 0, nil, err
	} else if !done && !s.tasks.cancel(t.ID) {
		return 0, nil, apiErr(http.StatusConflict, "the task has already ended")
	}
	s.audit(r, "task.cancel", deviceTarget(d), "cancelled task #%d (%s) on %q (API)", t.ID, taskText("en", t.Title, t.TitleArgs), d.Hostname)
	if t, err = s.store.Task(r.Context(), t.ID); err != nil {
		return 0, nil, err
	}
	return http.StatusAccepted, taskJSON(t), nil
}

func (s *Server) apiAlerts(r *http.Request, u *store.User) (int, any, error) {
	f := store.AlertFilter{Open: r.URL.Query().Get("state") != "all", Limit: 1000}
	f.DeviceID, _ = strconv.ParseInt(r.URL.Query().Get("device"), 10, 64)
	list, err := s.store.Alerts(r.Context(), u, f)
	if err != nil {
		return 0, nil, err
	}
	out := []map[string]any{}
	for _, a := range list {
		out = append(out, map[string]any{"id": a.ID, "device_id": a.DeviceID, "hostname": a.Hostname, "customer": a.Customer, "site": a.Site,
			"kind": a.Kind, "key": a.Key, "severity": a.Severity, "message": a.Message, "opened_at": a.OpenedAt, "resolved_at": a.ResolvedAt, "acknowledged_by": a.AckedBy})
	}
	return http.StatusOK, out, nil
}

func (s *Server) apiSoftware(r *http.Request, u *store.User) (int, any, error) {
	list, err := s.store.SoftwarePackages(r.Context())
	if err != nil {
		return 0, nil, err
	}
	out := []map[string]any{}
	for _, p := range list {
		out = append(out, map[string]any{"id": p.ID, "name": p.Name, "version": p.Version, "file": p.FileName, "kind": p.Kind, "size": p.Size, "sha256": p.SHA256})
	}
	return http.StatusOK, out, nil
}

func (s *Server) apiSoftwareInstall(r *http.Request, u *store.User) (int, any, error) {
	id, err := apiID(r, "id")
	if err != nil {
		return 0, nil, err
	}
	p, err := s.store.SoftwarePackage(r.Context(), id)
	if err != nil {
		return 0, nil, err
	}
	var q struct {
		Devices   []int64 `json:"devices"`
		Sites     []int64 `json:"sites"`
		Customers []int64 `json:"customers"`
	}
	if err := apiBody(r, &q); err != nil {
		return 0, nil, err
	}
	ids, err := s.windowsTargets(r.Context(), u, store.ScriptTarget{Devices: q.Devices, Sites: q.Sites, Customers: q.Customers})
	if err != nil {
		return 0, nil, err
	}
	if len(ids) == 0 {
		return 0, nil, apiErr(http.StatusBadRequest, "no Windows devices among the targets")
	}
	j, err := s.packageJob(r.Context(), u.Username, p, ids)
	if err != nil {
		return 0, nil, err
	}
	s.audit(r, "job.create", "job:"+strconv.FormatInt(j.ID, 10), "install software package %q %s on %d devices (API)", p.Name, p.Version, len(ids))
	go s.DispatchJobs(context.Background()) // #nosec G118 -- the job runs after the answer
	return http.StatusAccepted, map[string]any{"job_id": j.ID, "devices": len(ids)}, nil
}

func (s *Server) apiJob(r *http.Request, u *store.User) (int, any, error) {
	id, err := apiID(r, "id")
	if err != nil {
		return 0, nil, err
	}
	j, err := s.store.Job(r.Context(), id)
	if err != nil {
		return 0, nil, err
	}
	devs, err := s.store.JobDevices(r.Context(), id)
	if err != nil {
		return 0, nil, err
	}
	out := []map[string]any{}
	for _, d := range devs {
		if !u.SeesCustomer(d.CustomerID) {
			continue
		}
		out = append(out, map[string]any{"device_id": d.DeviceID, "hostname": d.Hostname, "status": d.Status, "exit_code": d.ExitCode, "error": d.Error})
	}
	if len(out) == 0 && !u.IsAdmin() {
		return 0, nil, store.ErrNotFound
	}
	return http.StatusOK, map[string]any{"id": j.ID, "name": j.Name, "created_by": j.CreatedBy, "created_at": j.CreatedAt, "expires_at": j.ExpiresAt, "devices": out}, nil
}

func (s *Server) apiPolicies(r *http.Request, u *store.User) (int, any, error) {
	list, err := s.store.Policies(r.Context())
	if err != nil {
		return 0, nil, err
	}
	as, err := s.store.Assignments(r.Context())
	if err != nil {
		return 0, nil, err
	}
	out := []map[string]any{}
	for _, p := range list {
		targets := []string{}
		for _, a := range as {
			if a.PolicyID == p.ID {
				targets = append(targets, a.TargetType+":"+strconv.FormatInt(a.TargetID, 10))
			}
		}
		out = append(out, map[string]any{"id": p.ID, "name": p.Name, "description": p.Description, "settings": p.Settings, "assigned_to": targets})
	}
	return http.StatusOK, out, nil
}

func (s *Server) apiPolicyAssign(r *http.Request, u *store.User) (int, any, error) {
	id, err := apiID(r, "id")
	if err != nil {
		return 0, nil, err
	}
	p, err := s.store.Policy(r.Context(), id)
	if err != nil {
		return 0, nil, err
	}
	var q struct {
		Target string `json:"target"`
	}
	if err := apiBody(r, &q); err != nil {
		return 0, nil, err
	}
	kind, tid, ok := parseTargetRef(q.Target)
	if !ok || !s.mayAssign(r.Context(), u, p, kind, tid) {
		return 0, nil, apiErr(http.StatusBadRequest, "target must be customer:ID, site:ID or device:ID")
	}
	if err := s.store.Assign(r.Context(), kind, tid, p.ID, u.Username); err != nil {
		return 0, nil, err
	}
	s.audit(r, "policy.assign", kind+":"+strconv.FormatInt(tid, 10), "assigned policy %q to %s #%d (API)", p.Name, kind, tid)
	return http.StatusOK, map[string]any{"policy_id": p.ID, "target": q.Target}, nil
}

func (s *Server) apiPolicyUnassign(r *http.Request, u *store.User) (int, any, error) {
	var q struct {
		Target string `json:"target"`
	}
	if err := apiBody(r, &q); err != nil {
		return 0, nil, err
	}
	kind, tid, ok := parseTargetRef(q.Target)
	if !ok {
		return 0, nil, apiErr(http.StatusBadRequest, "target must be customer:ID, site:ID or device:ID")
	}
	if err := s.store.Unassign(r.Context(), kind, tid); err != nil {
		return 0, nil, err
	}
	s.audit(r, "policy.unassign", kind+":"+strconv.FormatInt(tid, 10), "removed the policy of %s #%d (API)", kind, tid)
	return http.StatusOK, map[string]any{"target": q.Target}, nil
}
