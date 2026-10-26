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

// AgentPackage is the installer of one platform offered to agents.
type AgentPackage struct {
	Platform string
	File     string
	Version  string
	SHA256   string
	Size     int64
	Modified time.Time
	path     string
}

// packageFiles are the installer and its version file per platform.
var packageFiles = map[string][2]string{
	proto.PlatformWindows:    {AgentMSIName, "controlzit-agent-x64.json"},
	proto.PlatformLinuxAMD64: {"controlzit-agent-linux-amd64", "controlzit-agent-linux-amd64.json"},
	proto.PlatformLinuxARM64: {"controlzit-agent-linux-arm64", "controlzit-agent-linux-arm64.json"},
}

var platformOrder = []string{proto.PlatformWindows, proto.PlatformLinuxAMD64, proto.PlatformLinuxARM64}

type packageCache struct {
	mu   sync.Mutex
	pkgs map[string]*AgentPackage
	keys map[string]string // path + size + modification time of the cached hash
	last map[int64]time.Time
}

// packageFor returns the installer of a platform with its version and hash,
// or nil when there is none (or no version is known for it).
func (s *Server) packageFor(platform string) *AgentPackage {
	names, ok := packageFiles[platform]
	if !ok {
		return nil
	}
	p := s.download(names[0])
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
	raw, err := os.ReadFile(filepath.Join(s.DownloadsDir, names[1])) // #nosec G304 -- fixed name in the data directory
	if err != nil || json.Unmarshal(raw, &meta) != nil || !proto.ValidVersion(meta.Version) {
		return nil
	}
	key := p + "|" + strconv.FormatInt(fi.Size(), 10) + "|" + fi.ModTime().String() + "|" + meta.Version
	s.pkg.mu.Lock()
	defer s.pkg.mu.Unlock()
	if s.pkg.pkgs == nil {
		s.pkg.pkgs, s.pkg.keys = map[string]*AgentPackage{}, map[string]string{}
	}
	if s.pkg.keys[platform] == key && s.pkg.pkgs[platform] != nil {
		return s.pkg.pkgs[platform]
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
	pk := &AgentPackage{Platform: platform, File: names[0], Version: meta.Version, SHA256: hex.EncodeToString(h.Sum(nil)), Size: fi.Size(), Modified: fi.ModTime(), path: p}
	s.pkg.pkgs[platform], s.pkg.keys[platform] = pk, key
	return pk
}

// Outdated reports whether an agent version is older than the package.
func (p *AgentPackage) Outdated(v string) bool {
	return p != nil && v != "" && proto.CompareVersions(v, p.Version) < 0
}

// Packages are the installers of all platforms (console views).
type Packages struct {
	List []*AgentPackage
	by   map[string]*AgentPackage
}

func (s *Server) packages() *Packages {
	ps := &Packages{by: map[string]*AgentPackage{}}
	for _, pl := range platformOrder {
		if pk := s.packageFor(pl); pk != nil {
			ps.List = append(ps.List, pk)
			ps.by[pl] = pk
		}
	}
	return ps
}

// For is the package a device updates to (Linux: the x86-64 one stands for
// the version of both architectures).
func (p *Packages) For(d *store.Device) *AgentPackage {
	if p == nil {
		return nil
	}
	if d.IsWindows() {
		return p.by[proto.PlatformWindows]
	}
	if pk := p.by[proto.PlatformLinuxAMD64]; pk != nil {
		return pk
	}
	return p.by[proto.PlatformLinuxARM64]
}

// Offers reports whether a newer agent is available for the device.
func (p *Packages) Offers(d *store.Device) bool { return p.For(d).Outdated(d.AgentVersion) }

// devicePlatform is the package platform of a device (Linux: from the CPU
// architecture in its inventory).
func (s *Server) devicePlatform(ctx context.Context, d *store.Device) string {
	if d.IsWindows() {
		return proto.PlatformWindows
	}
	if full, err := s.store.Device(ctx, d.ID); err == nil && full.Inventory != nil && full.Inventory.OS.Arch == "arm64" {
		return proto.PlatformLinuxARM64
	}
	return proto.PlatformLinuxAMD64
}

// handlePackage serves the installer to enrolled agents (agent endpoint);
// agents name their platform (older Windows agents do not).
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
	platform := r.URL.Query().Get("platform")
	if platform == "" {
		platform = proto.PlatformWindows
	}
	pkg := s.packageFor(platform)
	if pkg == nil {
		agentError(w, http.StatusNotFound, "no agent installer for "+platform+" on the server")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, pkg.path)
}

// updateDevice sends agent.update to a connected device.
func (s *Server) updateDevice(ctx context.Context, d *store.Device, issuer string) error {
	pkg := s.packageFor(s.devicePlatform(ctx, d))
	if pkg == nil {
		return errors.New("there is no agent installer with a known version for this device on the server")
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
	pkg := s.packages().For(d)
	if !pkg.Outdated(version) {
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
	if _, err := s.queueTask(ctx, d, "system", "agent.update", "Update the agent to %s (automatic)", []string{pkg.Version}, struct{}{}); err != nil {
		s.log.Warn("automatic agent update failed", "device", d.ID, "err", err)
	}
}

// ---- console

type agentUpdatesData struct {
	Settings AgentUpdateSettings
	Packages *Packages
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
	d := &agentUpdatesData{Settings: s.AgentUpdate(r.Context()), Packages: s.packages(), Devices: list, Online: map[int64]bool{}}
	for _, dev := range list {
		d.Online[dev.ID] = s.Connected(dev.ID)
		if d.Packages.Offers(dev) {
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

// packagePlatform tells the platform of an uploaded installer from its
// first bytes: an MSI (OLE file) or a Linux program (ELF, x86-64 or ARM64).
func packagePlatform(head []byte) string {
	switch {
	case len(head) >= 8 && string(head[:8]) == "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
		return proto.PlatformWindows
	case len(head) >= 20 && string(head[:4]) == "\x7fELF" && head[4] == 2 && head[5] == 1: // 64-bit, little-endian
		switch uint16(head[18]) | uint16(head[19])<<8 { // e_machine
		case 0x3e:
			return proto.PlatformLinuxAMD64
		case 0xb7:
			return proto.PlatformLinuxARM64
		}
	}
	return ""
}

// handlePackageUpload replaces an installer: the MSI or a Linux agent of a
// release.
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
	head := make([]byte, 20)
	n, _ := io.ReadFull(file, head)
	head = head[:n]
	platform := packagePlatform(head)
	if platform == "" {
		s.redirect(w, r, back, "This is neither the Windows installer (.msi) nor a Linux agent.")
		return
	}
	names := packageFiles[platform]
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
	if err := os.Rename(tmp.Name(), filepath.Join(s.DownloadsDir, names[0])); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := os.WriteFile(filepath.Join(s.DownloadsDir, names[1]), meta, 0o600); err != nil {
		s.serverError(w, r, err)
		return
	}
	pkg := s.packageFor(platform)
	if pkg == nil {
		s.redirect(w, r, back, "The upload failed.")
		return
	}
	s.audit(r, "agent.package", "settings", "uploaded agent installer %s for %s (%s, %d bytes, SHA-256 %s)", pkg.Version, platform, hdr.Filename, pkg.Size, pkg.SHA256)
	s.redirect(w, r, back, translate(s.lang(r, userFrom(r)), "Agent installer %s uploaded.", pkg.Version))
}

// handleUpdateAll updates every connected, outdated agent now.
func (s *Server) handleUpdateAll(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.Devices(r.Context(), userFrom(r), store.DeviceFilter{Limit: 2000})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	pkgs := s.packages()
	issuer := s.issuer(r)
	queued := 0
	for _, d := range list {
		if !pkgs.Offers(d) || !s.Connected(d.ID) {
			continue
		}
		if _, err := s.queueTask(r.Context(), d, issuer, "agent.update", "Update the agent to %s", []string{pkgs.For(d).Version}, struct{}{}); err != nil {
			s.serverError(w, r, err)
			return
		}
		queued++
	}
	s.audit(r, "agent.update", "agents", "update of %d online agents queued", queued)
	s.redirect(w, r, "/settings/agents", translate(s.lang(r, userFrom(r)), "Update started on %d agents; each device shows it under Activity.", queued))
}

// handleDeviceUpdate updates one device's agent (device page).
func (s *Server) handleDeviceUpdate(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	back := s.deviceURL(d, "")
	pkg := s.packageFor(s.devicePlatform(r.Context(), d))
	if pkg == nil {
		s.redirect(w, r, back, "there is no agent installer with a known version for this device on the server")
		return
	}
	s.startTask(w, r, d, "agent.update", "Update the agent to %s", []string{pkg.Version}, struct{}{})
}
