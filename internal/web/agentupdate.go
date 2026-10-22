package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

// Agent updates: the installer in <data-dir>/downloads is the version the
// agents should run. Its version is in a small JSON file next to it (written
// when it is uploaded in the console or by the release scripts); its hash is
// computed here. Agents get a signed agent.update command with the version
// and the hash, download the installer from the agent endpoint and check it.

const (
	settingAgentUpdate = "agent_update"
	packageMeta        = "controlzit-agent-x64.json"
	// autoRetry is how long the server waits before offering the same
	// device an update again.
	autoRetry = time.Hour
)

// AgentUpdateSettings control automatic updates.
type AgentUpdateSettings struct {
	// Auto updates outdated agents when they connect (default on).
	Auto bool `json:"auto"`
}

// AgentUpdate loads the update settings.
func (s *Server) AgentUpdate(ctx context.Context) AgentUpdateSettings {
	x := AgentUpdateSettings{Auto: true}
	if err := s.store.GetSetting(ctx, settingAgentUpdate, &x); err != nil {
		return AgentUpdateSettings{Auto: true}
	}
	return x
}

// AgentPackage is the installer offered to agents.
type AgentPackage struct {
	Version  string
	SHA256   string
	Size     int64
	Modified time.Time
	path     string
}

type packageCache struct {
	mu   sync.Mutex
	pkg  *AgentPackage
	key  string // path + size + modification time of the cached hash
	last map[int64]time.Time
}

// agentPackage returns the installer with its version and hash, or nil when
// there is none (or no version is known for it).
func (s *Server) agentPackage() *AgentPackage {
	p := s.agentMSI()
	if p == "" {
		return nil
	}
	fi, err := os.Stat(p)
	if err != nil {
		return nil
	}
	var meta struct {
		Version string `json:"version"`
	}
	raw, err := os.ReadFile(filepath.Join(s.DownloadsDir, packageMeta)) // #nosec G304 -- fixed name in the data directory
	if err != nil || json.Unmarshal(raw, &meta) != nil || !proto.ValidVersion(meta.Version) {
		return nil
	}
	key := p + "|" + strconv.FormatInt(fi.Size(), 10) + "|" + fi.ModTime().String() + "|" + meta.Version
	s.pkg.mu.Lock()
	defer s.pkg.mu.Unlock()
	if s.pkg.key == key && s.pkg.pkg != nil {
		return s.pkg.pkg
	}
	f, err := os.Open(p) // #nosec G304 -- the installer in the data directory
	if err != nil {
		return nil
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil
	}
	s.pkg.pkg = &AgentPackage{Version: meta.Version, SHA256: hex.EncodeToString(h.Sum(nil)), Size: fi.Size(), Modified: fi.ModTime(), path: p}
	s.pkg.key = key
	return s.pkg.pkg
}

// Outdated reports whether an agent version is older than the package.
func (p *AgentPackage) Outdated(v string) bool {
	return p != nil && v != "" && proto.CompareVersions(v, p.Version) < 0
}

// Offers reports whether the package updates the device (the MSI is for
// Windows agents only).
func (p *AgentPackage) Offers(d *store.Device) bool {
	return d.IsWindows() && p.Outdated(d.AgentVersion)
}

// handlePackage serves the installer to enrolled agents (agent endpoint).
func (s *Server) handlePackage(w http.ResponseWriter, r *http.Request) {
	pub := peerKey(r)
	if pub == nil {
		agentError(w, http.StatusUnauthorized, "an ed25519 client certificate is required")
		return
	}
	if _, err := s.store.DeviceByKey(r.Context(), pub); err != nil {
		agentError(w, http.StatusUnauthorized, "unknown agent")
		return
	}
	pkg := s.agentPackage()
	if pkg == nil {
		agentError(w, http.StatusNotFound, "no agent installer on the server")
		return
	}
	w.Header().Set("Content-Type", "application/x-msi")
	http.ServeFile(w, r, pkg.path)
}

// updateDevice sends agent.update to a connected device.
func (s *Server) updateDevice(ctx context.Context, d *store.Device, issuer string) error {
	pkg := s.agentPackage()
	if pkg == nil {
		return errors.New("there is no agent installer with a known version on the server")
	}
	if !d.IsWindows() {
		return errors.New("this agent runs on Linux and is updated with the Linux installer")
	}
	if !pkg.Outdated(d.AgentVersion) {
		return errors.New("the agent already runs this version")
	}
	var res struct {
		Started bool `json:"started"`
	}
	err := s.call(ctx, d.ID, issuer, proto.KindAgentUpdate, proto.AgentUpdate{Version: pkg.Version, SHA256: pkg.SHA256, Size: pkg.Size}, &res, 10*time.Minute)
	if err == nil && !res.Started {
		err = errors.New("the agent did not start the update")
	}
	return err
}

// autoUpdate offers the package to a device that just connected with an
// older agent (at most once per autoRetry).
func (s *Server) autoUpdate(d *store.Device, version string) {
	pkg := s.agentPackage()
	if !d.IsWindows() || !pkg.Outdated(version) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	if !s.AgentUpdate(ctx).Auto {
		return
	}
	s.pkg.mu.Lock()
	if s.pkg.last == nil {
		s.pkg.last = map[int64]time.Time{}
	}
	if t, ok := s.pkg.last[d.ID]; ok && s.now().Sub(t) < autoRetry {
		s.pkg.mu.Unlock()
		return
	}
	s.pkg.last[d.ID] = s.now()
	s.pkg.mu.Unlock()
	time.Sleep(5 * time.Second) // let the channel settle (welcome, first heartbeat)
	dd := *d
	dd.AgentVersion = version
	err := s.updateDevice(ctx, &dd, "system")
	target := "device:" + strconv.FormatInt(d.ID, 10)
	if err != nil {
		s.log.Warn("automatic agent update failed", "device", d.ID, "err", err)
		_ = s.store.Audit(ctx, "system", "", "agent.update", target, "automatic update of "+d.Hostname+" from "+version+" to "+pkg.Version+" failed: "+err.Error())
		return
	}
	_ = s.store.Audit(ctx, "system", "", "agent.update", target, "automatic update of "+d.Hostname+" from "+version+" to "+pkg.Version+" started")
}

// ---- console

type agentUpdatesData struct {
	Settings AgentUpdateSettings
	Package  *AgentPackage
	Devices  []*store.Device
	Outdated int
	Online   map[int64]bool
}

func (s *Server) handleAgentUpdates(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.Devices(r.Context(), userFrom(r), store.DeviceFilter{Limit: 2000})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := &agentUpdatesData{Settings: s.AgentUpdate(r.Context()), Package: s.agentPackage(), Devices: list, Online: map[int64]bool{}}
	for _, dev := range list {
		d.Online[dev.ID] = s.Connected(dev.ID)
		if d.Package.Offers(dev) {
			d.Outdated++
		}
	}
	s.render(w, r, http.StatusOK, "agentupdates", &Page{Title: "Agent updates", Nav: "settings", Data: d})
}

func (s *Server) handleAgentUpdatesSave(w http.ResponseWriter, r *http.Request) {
	x := AgentUpdateSettings{Auto: r.FormValue("auto") == "1"}
	if err := s.store.SetSetting(r.Context(), settingAgentUpdate, x); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.agent_update", "settings", "automatic agent updates: %v", x.Auto)
	s.redirect(w, r, "/settings/agents", "Saved.")
}

var msiVersionRE = regexp.MustCompile(`(\d+\.\d+\.\d+)`)

// handlePackageUpload replaces the installer (an MSI from a release).
func (s *Server) handlePackageUpload(w http.ResponseWriter, r *http.Request) {
	back := "/settings/agents"
	if s.DownloadsDir == "" {
		s.redirect(w, r, back, "The server has no downloads folder.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, proto.MaxPackageSize+1<<20)
	file, hdr, err := r.FormFile("file")
	if err != nil {
		s.redirect(w, r, back, "Choose the agent installer (.msi).")
		return
	}
	defer file.Close()
	version := strings.TrimSpace(r.FormValue("version"))
	if version == "" {
		version = msiVersionRE.FindString(hdr.Filename)
	}
	if !proto.ValidVersion(version) {
		s.redirect(w, r, back, "Enter the version of the installer (for example 0.2.8).")
		return
	}
	head := make([]byte, 8)
	if _, err := io.ReadFull(file, head); err != nil || string(head) != "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" {
		s.redirect(w, r, back, "This is not a Windows Installer package (.msi).")
		return
	}
	if err := os.MkdirAll(s.DownloadsDir, 0o750); err != nil {
		s.serverError(w, r, err)
		return
	}
	tmp, err := os.CreateTemp(s.DownloadsDir, ".upload-*")
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(head)
	if err == nil {
		_, err = io.Copy(tmp, file)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		s.redirect(w, r, back, "The upload failed.")
		return
	}
	meta, _ := json.Marshal(map[string]string{"version": version})
	if err := os.Rename(tmp.Name(), filepath.Join(s.DownloadsDir, AgentMSIName)); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := os.WriteFile(filepath.Join(s.DownloadsDir, packageMeta), meta, 0o600); err != nil {
		s.serverError(w, r, err)
		return
	}
	pkg := s.agentPackage()
	if pkg == nil {
		s.redirect(w, r, back, "The upload failed.")
		return
	}
	s.audit(r, "agent.package", "settings", "uploaded agent installer %s (%s, %d bytes, SHA-256 %s)", pkg.Version, hdr.Filename, pkg.Size, pkg.SHA256)
	s.redirect(w, r, back, translate(s.lang(r, userFrom(r)), "Agent installer %s uploaded.", pkg.Version))
}

// handleUpdateAll updates every connected, outdated agent now.
func (s *Server) handleUpdateAll(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.Devices(r.Context(), userFrom(r), store.DeviceFilter{Limit: 2000})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	pkg := s.agentPackage()
	issuer := s.issuer(r)
	started, failed := 0, 0
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, d := range list {
		if !pkg.Offers(d) || !s.Connected(d.ID) {
			continue
		}
		wg.Add(1)
		go func(d *store.Device) {
			defer wg.Done()
			err := s.updateDevice(r.Context(), d, issuer)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed++
				s.audit(r, "agent.update", "device:"+strconv.FormatInt(d.ID, 10), "update of %q from %s to %s failed: %v", d.Hostname, d.AgentVersion, pkg.Version, err)
				return
			}
			started++
			s.audit(r, "agent.update", "device:"+strconv.FormatInt(d.ID, 10), "update of %q from %s to %s started", d.Hostname, d.AgentVersion, pkg.Version)
		}(d)
	}
	wg.Wait()
	s.redirect(w, r, "/settings/agents", translate(s.lang(r, userFrom(r)), "Update started on %d agents (%d failed).", started, failed))
}

// handleDeviceUpdate updates one device's agent (device page).
func (s *Server) handleDeviceUpdate(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	back := s.deviceURL(d, "")
	pkg := s.agentPackage()
	if err := s.updateDevice(r.Context(), d, s.issuer(r)); err != nil {
		s.audit(r, "agent.update", deviceTarget(d), "update of %q failed: %v", d.Hostname, err)
		s.redirect(w, r, back, err.Error())
		return
	}
	s.audit(r, "agent.update", deviceTarget(d), "update of %q from %s to %s started", d.Hostname, d.AgentVersion, pkg.Version)
	s.redirect(w, r, back, translate(s.lang(r, userFrom(r)), "The agent is updating to %s; the device reconnects in a minute.", pkg.Version))
}
