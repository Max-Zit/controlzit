package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

// Software library: installers (MSI, EXE) uploaded by administrators and
// installed silently on devices as jobs (offline devices install when they
// connect, within 24 hours). Agents download an installer from the agent
// endpoint; its hash and the command line come in the signed command.
// Chocolatey is an optional second public source next to winget.

const (
	packageJobTimeout = 25 * 60 // seconds; a command lives at most 30 minutes
	settingSoftware   = "software"
)

// SoftwareSettings are the software sources besides winget.
type SoftwareSettings struct {
	Chocolatey bool `json:"chocolatey"`
}

func (s *Server) softwareSettings(ctx context.Context) SoftwareSettings {
	var x SoftwareSettings
	_ = s.store.GetSetting(ctx, settingSoftware, &x)
	return x
}

func (s *Server) libraryDir() (string, error) {
	if s.DataDir == "" {
		return "", errors.New("the server has no data directory")
	}
	dir := filepath.Join(s.DataDir, "library")
	return dir, os.MkdirAll(dir, 0o750)
}

// ---- pages

type swLibraryData struct {
	Packages []store.SoftwarePackage
	Jobs     []store.ScriptJob
	Settings SoftwareSettings
}

func (s *Server) handleSwLibrary(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if !u.CanWrite() {
		s.forbidden(w, r)
		return
	}
	list, err := s.store.SoftwarePackages(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	jobs, err := s.store.Jobs(r.Context(), jobOwner(u), 0, 60)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := &swLibraryData{Packages: list, Settings: s.softwareSettings(r.Context())}
	for _, j := range jobs {
		if j.Shell == "package" && len(d.Jobs) < 20 {
			d.Jobs = append(d.Jobs, j)
		}
	}
	s.render(w, r, http.StatusOK, "swlibrary", &Page{Title: "Software library", Nav: "software", Data: d})
}

func (s *Server) handleSwSettings(w http.ResponseWriter, r *http.Request) {
	x := SoftwareSettings{Chocolatey: r.FormValue("chocolatey") == "1"}
	if err := s.store.SetSetting(r.Context(), settingSoftware, x); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.software", "settings", "software sources: Chocolatey %v", x.Chocolatey)
	s.redirect(w, r, "/software", "Saved.")
}

func (s *Server) swPackageFor(w http.ResponseWriter, r *http.Request) *store.SoftwarePackage {
	if !userFrom(r).CanWrite() {
		s.forbidden(w, r)
		return nil
	}
	id, ok := pathID(r, "pid")
	if !ok {
		s.notFound(w, r)
		return nil
	}
	p, err := s.store.SoftwarePackage(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, r)
		return nil
	}
	if err != nil {
		s.serverError(w, r, err)
		return nil
	}
	return p
}

type swPackageData struct {
	P       *store.SoftwarePackage
	Codes   string
	Command string
}

func (s *Server) handleSwPackage(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("pid") == "" { // /software/new
		if !userFrom(r).IsAdmin() {
			s.forbidden(w, r)
			return
		}
		s.render(w, r, http.StatusOK, "swpackage", &Page{Title: "Add a package", Nav: "software", Data: &swPackageData{P: &store.SoftwarePackage{}, Codes: "0, 1641, 3010"}})
		return
	}
	p := s.swPackageFor(w, r)
	if p == nil {
		return
	}
	s.render(w, r, http.StatusOK, "swpackage", &Page{Title: p.Name, Nav: "software", Data: &swPackageData{P: p, Codes: joinCodes(p.SuccessCodes), Command: installCommand(packageInstall(p))}})
}

func joinCodes(c []int) string {
	parts := make([]string, len(c))
	for i, n := range c {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ", ")
}

func parseCodes(s string) ([]int, bool) {
	var out []int
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		n, err := strconv.Atoi(f)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, len(out) > 0 && len(out) <= 20
}

// installCommand is what the agent runs, for the page and the run record.
func installCommand(p proto.PackageInstall) string {
	cmd := `"` + p.FileName + `"`
	if p.Kind == "msi" {
		cmd = `msiexec.exe /i "` + p.FileName + `" /l*v install.log`
	}
	if p.Args != "" {
		cmd += " " + p.Args
	}
	return cmd
}

func packageInstall(p *store.SoftwarePackage) proto.PackageInstall {
	return proto.PackageInstall{Name: p.Name, Version: p.Version, FileName: p.FileName, Kind: p.Kind, SHA256: p.SHA256, Size: p.Size, Args: p.Args, Success: p.SuccessCodes}
}

var versionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+\-]{0,39}$`)

// swForm reads and checks the details of a package.
func swForm(p *store.SoftwarePackage, get func(string) string) string {
	p.Name, p.Version = strings.TrimSpace(get("name")), strings.TrimSpace(get("version"))
	p.Description, p.Args = strings.TrimSpace(get("description")), strings.TrimSpace(get("args"))
	if p.Name == "" || len(p.Name) > 120 || len(p.Description) > 1000 {
		return "Enter a name (up to 120 characters)."
	}
	if p.Version != "" && !versionRE.MatchString(p.Version) {
		return "The version may contain letters, digits, dots and dashes (up to 40 characters)."
	}
	if !proto.ValidArgs(p.Args) {
		return "The arguments must be one line of up to 1000 characters."
	}
	codes, ok := parseCodes(get("codes"))
	if !ok {
		return "Enter the exit codes that mean success, for example 0, 1641, 3010."
	}
	p.SuccessCodes = codes
	return ""
}

func (s *Server) handleSwPackageSave(w http.ResponseWriter, r *http.Request) {
	p := s.swPackageFor(w, r)
	if p == nil {
		return
	}
	back := "/software/" + strconv.FormatInt(p.ID, 10)
	if msg := swForm(p, r.FormValue); msg != "" {
		s.redirect(w, r, back, msg)
		return
	}
	p.UpdatedBy = s.issuer(r)
	if err := s.store.SaveSoftwarePackage(r.Context(), p); errors.Is(err, store.ErrConflict) {
		s.redirect(w, r, back, "A package with this name and version already exists.")
		return
	} else if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "package.save", "package:"+strconv.FormatInt(p.ID, 10), "saved software package %q %s: %s", p.Name, p.Version, installCommand(packageInstall(p)))
	s.redirect(w, r, back, "Saved.")
}

func (s *Server) handleSwPackageDelete(w http.ResponseWriter, r *http.Request) {
	p := s.swPackageFor(w, r)
	if p == nil {
		return
	}
	shared, err := s.store.DeleteSoftwarePackage(r.Context(), p.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if dir, err := s.libraryDir(); err == nil && !shared {
		_ = os.Remove(filepath.Join(dir, p.SHA256))
	}
	s.audit(r, "package.delete", "package:"+strconv.FormatInt(p.ID, 10), "deleted software package %q %s (%s)", p.Name, p.Version, p.FileName)
	s.redirect(w, r, "/software", translate(s.lang(r, userFrom(r)), "Package %s deleted.", p.Name))
}

// ---- upload

var (
	msiMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
	badName  = regexp.MustCompile(`[^A-Za-z0-9 ._()+\-]`)
)

// installerName makes a safe file name from the uploaded one.
func installerName(name, kind string) string {
	name = filepath.Base(strings.ReplaceAll(name, `\`, "/"))
	base := strings.TrimSuffix(name, filepath.Ext(name))
	base = strings.TrimLeft(badName.ReplaceAllString(base, "_"), " ._()+-")
	if len(base) > 120 {
		base = base[:120]
	}
	if base == "" {
		base = "installer"
	}
	return base + "." + kind
}

// handleSwUpload stores an uploaded installer while it streams in (the
// file field comes last in the form) and adds the package.
func (s *Server) handleSwUpload(w http.ResponseWriter, r *http.Request) {
	const back = "/software/new"
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{}) // large installers take a while
	_ = rc.SetWriteDeadline(time.Time{})
	r.Body = http.MaxBytesReader(w, r.Body, proto.MaxLibraryPackage+1<<20)
	dir, err := s.libraryDir()
	if err != nil {
		s.redirect(w, r, back, err.Error())
		return
	}
	mr, err := r.MultipartReader()
	if err != nil {
		s.redirect(w, r, back, "Choose the installer (.msi or .exe).")
		return
	}
	fields := map[string]string{}
	p := &store.SoftwarePackage{UpdatedBy: s.issuer(r)}
	var tmp string
	defer func() {
		if tmp != "" {
			_ = os.Remove(tmp)
		}
	}()
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			s.redirect(w, r, back, "The upload failed.")
			return
		}
		if part.FormName() != "file" {
			b, _ := io.ReadAll(io.LimitReader(part, 4<<10))
			fields[part.FormName()] = string(b)
			continue
		}
		if p.SHA256 != "" || part.FileName() == "" {
			continue
		}
		if tmp, err = s.receiveInstaller(dir, part, p); err != nil {
			s.redirect(w, r, back, err.Error())
			return
		}
	}
	if tmp == "" {
		s.redirect(w, r, back, "Choose the installer (.msi or .exe).")
		return
	}
	if fields["codes"] == "" {
		fields["codes"] = "0, 1641, 3010"
	}
	if msg := swForm(p, func(k string) string { return fields[k] }); msg != "" {
		s.redirect(w, r, back, msg)
		return
	}
	if p.Kind == "msi" && p.Args == "" {
		p.Args = "/qn /norestart"
	}
	if p.Kind == "exe" && p.Args == "" {
		s.redirect(w, r, back, "An EXE installer needs the arguments for a silent installation (for example /S or /quiet).")
		return
	}
	if err := os.Rename(tmp, filepath.Join(dir, p.SHA256)); err != nil {
		s.serverError(w, r, err)
		return
	}
	tmp = ""
	if err := s.store.SaveSoftwarePackage(r.Context(), p); errors.Is(err, store.ErrConflict) {
		s.redirect(w, r, back, "A package with this name and version already exists.")
		return
	} else if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "package.add", "package:"+strconv.FormatInt(p.ID, 10), "added software package %q %s: %s (%d bytes, SHA-256 %s)", p.Name, p.Version, p.FileName, p.Size, p.SHA256)
	s.redirect(w, r, "/software/"+strconv.FormatInt(p.ID, 10), translate(s.lang(r, userFrom(r)), "Package %s added.", p.Name))
}

// receiveInstaller writes the file part to a temporary file of the library
// and fills its name, kind, size and hash.
func (s *Server) receiveInstaller(dir string, part *multipart.Part, p *store.SoftwarePackage) (string, error) {
	head := make([]byte, 8)
	n, _ := io.ReadFull(part, head)
	head = head[:n]
	switch {
	case bytes.HasPrefix(head, msiMagic):
		p.Kind = "msi"
	case bytes.HasPrefix(head, []byte("MZ")):
		p.Kind = "exe"
	default:
		return "", uiErr("This is neither a Windows Installer package (.msi) nor a program (.exe).")
	}
	f, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(f, h), io.MultiReader(bytes.NewReader(head), part))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", uiErr("The upload failed.")
	}
	p.FileName, p.Size, p.SHA256 = installerName(part.FileName(), p.Kind), size, hex.EncodeToString(h.Sum(nil))
	return f.Name(), nil
}

// ---- installing on devices

func (s *Server) handleSwRunNew(w http.ResponseWriter, r *http.Request) {
	p := s.swPackageFor(w, r)
	if p == nil {
		return
	}
	td, err := s.targets(r, true)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	td.P = p
	s.render(w, r, http.StatusOK, "swrun", &Page{Title: p.Name, Nav: "software", Data: td})
}

func (s *Server) handleSwRun(w http.ResponseWriter, r *http.Request) {
	p := s.swPackageFor(w, r)
	if p == nil {
		return
	}
	u := userFrom(r)
	t := parseTarget(r)
	if t.All && !u.IsAdmin() && !u.AllCustomers {
		t.All = false
	}
	back := "/software/" + strconv.FormatInt(p.ID, 10) + "/run"
	ids, err := s.windowsTargets(r.Context(), u, t)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(ids) == 0 {
		s.redirect(w, r, back, "Choose the Windows devices.")
		return
	}
	j, err := s.packageJob(r.Context(), u.Username, p, ids)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "job.create", "job:"+strconv.FormatInt(j.ID, 10), "install software package %q %s on %d devices", p.Name, p.Version, len(ids))
	go s.DispatchJobs(context.Background()) // #nosec G118 -- the job runs after the page has answered
	s.redirect(w, r, "/jobs/"+strconv.FormatInt(j.ID, 10), "")
}

// windowsTargets resolves a target to the Windows devices the user may use.
func (s *Server) windowsTargets(ctx context.Context, u *store.User, t store.ScriptTarget) ([]int64, error) {
	if t.Empty() {
		return nil, nil
	}
	ids, err := s.store.ResolveTarget(ctx, u, t)
	if err != nil {
		return nil, err
	}
	out := ids[:0]
	for _, id := range ids {
		if d, err := s.store.Device(ctx, id); err == nil && d.IsWindows() {
			out = append(out, id)
		}
	}
	return out, nil
}

func (s *Server) packageJob(ctx context.Context, by string, p *store.SoftwarePackage, devices []int64) (*store.ScriptJob, error) {
	body, err := json.Marshal(packageInstall(p))
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(p.Name + " " + p.Version)
	j := &store.ScriptJob{Name: name, Shell: "package", Body: string(body), Timeout: packageJobTimeout, CreatedBy: by, ExpiresAt: s.now().Add(jobLifetime)}
	return j, s.store.CreateJob(ctx, j, devices)
}

// runPackage installs a package of a job on a device and records the run.
func (s *Server) runPackage(ctx context.Context, d *store.Device, issuer, body string, jobID *int64) (*store.ScriptRun, bool, error) {
	var p proto.PackageInstall
	if err := json.Unmarshal([]byte(body), &p); err != nil || !p.Valid() {
		return nil, false, errors.New("bad package job")
	}
	run := &store.ScriptRun{DeviceID: d.ID, Username: issuer, Shell: "package", StartedAt: s.now(), JobID: jobID,
		Script: strings.TrimSpace(p.Name+" "+p.Version) + "\n" + installCommand(p) + "\nSHA-256 " + p.SHA256}
	var res proto.PackageResult
	err := s.call(ctx, d.ID, issuer, proto.KindPackageInstall, p, &res, 27*time.Minute)
	ok := false
	if err != nil {
		run.Error = err.Error()
	} else {
		code := res.ExitCode
		run.ExitCode, run.Output, ok = &code, res.Output, res.OK
	}
	run.Duration = s.now().Sub(run.StartedAt)
	if err := s.store.AddScriptRun(context.WithoutCancel(ctx), run); err != nil {
		return nil, false, err
	}
	return run, ok, nil
}

// handleLibraryFile serves an installer of the library to an agent.
func (s *Server) handleLibraryFile(w http.ResponseWriter, r *http.Request) {
	pub := peerKey(r)
	if pub == nil {
		agentError(w, http.StatusUnauthorized, "an ed25519 client certificate is required")
		return
	}
	if _, err := s.store.DeviceByKey(r.Context(), pub); err != nil {
		agentError(w, http.StatusUnauthorized, "unknown agent")
		return
	}
	sum := r.URL.Query().Get("sha256")
	known, err := s.store.SoftwarePackageFile(r.Context(), sum)
	if !proto.ValidSHA256(sum) || err != nil || !known {
		agentError(w, http.StatusNotFound, "no such package")
		return
	}
	dir, err := s.libraryDir()
	if err != nil {
		agentError(w, http.StatusNotFound, "no such package")
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{}) // large installers
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, filepath.Join(dir, sum)) // #nosec G703 -- sum is a checked hex SHA-256 of a library package
}

// ---- target choice shared with script jobs

// targets loads the customers, sites and devices a user can choose from.
func (s *Server) targets(r *http.Request, windowsOnly bool) (*targetData, error) {
	u := userFrom(r)
	td := &targetData{Online: map[int64]bool{}}
	var err error
	if td.Customers, err = s.store.Customers(r.Context(), u); err != nil {
		return nil, err
	}
	for _, c := range td.Customers {
		sites, err := s.store.Sites(r.Context(), c.ID)
		if err != nil {
			return nil, err
		}
		td.Sites = append(td.Sites, sites...)
	}
	devs, err := s.store.Devices(r.Context(), u, store.DeviceFilter{Limit: 2000})
	if err != nil {
		return nil, err
	}
	for _, d := range devs {
		if windowsOnly && !d.IsWindows() {
			continue
		}
		td.Devices = append(td.Devices, d)
		td.Online[d.ID] = s.Connected(d.ID)
	}
	return td, nil
}
