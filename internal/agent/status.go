package agent

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Status is what the service publishes for the tray icon. It holds no
// secrets; the file is readable by all users of the machine.
type Status struct {
	Version     string    `json:"version"`
	Server      string    `json:"server"` // host only
	Customer    string    `json:"customer"`
	Site        string    `json:"site"`
	Connected   bool      `json:"connected"`
	Since       time.Time `json:"since"`
	LastContact time.Time `json:"last_contact"`
	Updated     time.Time `json:"updated"`
	// For the agent window.
	Hostname string         `json:"hostname"`
	OS       string         `json:"os"`
	DeviceID int64          `json:"device_id"`
	BootTime time.Time      `json:"boot_time,omitzero"`
	Updates  *UpdateSummary `json:"updates,omitempty"`
}

// UpdateSummary is the Windows Update / package state for the window.
type UpdateSummary struct {
	ScannedAt      time.Time `json:"scanned_at,omitzero"`
	Missing        int       `json:"missing"`
	Security       int       `json:"security"`
	RebootRequired bool      `json:"reboot_required"`
	State          string    `json:"state"`
}

const statusFile = "agent-status.json"

// StatusPath is where the service writes its status: a folder all users can
// read (ProgramData\ControlZit) when running as the service, else the data
// directory (test runs).
func StatusPath(dir string) string {
	if p := publicStatusDir(); p != "" {
		return filepath.Join(p, statusFile)
	}
	return filepath.Join(dir, statusFile)
}

var statusMu sync.Mutex

// publishStatus updates the status file (best effort).
func (a *Agent) publishStatus(connected bool) {
	statusMu.Lock()
	defer statusMu.Unlock()
	now := time.Now().UTC()
	if connected != a.status.Connected || a.status.Since.IsZero() {
		a.status.Since = now
	}
	a.status.Connected = connected
	if connected {
		a.status.LastContact = now
	}
	a.status.Version = Version
	if u, err := url.Parse(a.Cfg.ServerURL); err == nil {
		a.status.Server = u.Hostname()
	}
	a.status.Customer, a.status.Site, a.status.Updated = a.Cfg.Customer, a.Cfg.Site, now
	a.status.DeviceID = a.Cfg.DeviceID
	if a.Info != nil {
		si := a.Info()
		a.status.OS, a.status.BootTime = si.OS, si.BootTime
	}
	a.status.Hostname, _ = os.Hostname()
	if a.patch != nil {
		a.patch.mu.Lock()
		r := a.patch.report
		a.patch.mu.Unlock()
		u := &UpdateSummary{ScannedAt: r.ScannedAt, Missing: len(r.Updates), RebootRequired: r.RebootRequired, State: r.State}
		for i := range r.Updates {
			if r.Updates[i].Security() {
				u.Security++
			}
		}
		a.status.Updates = u
	}
	b, _ := json.MarshalIndent(a.status, "", "  ")
	p := StatusPath(a.Dir)
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil { // #nosec G306 -- public status, no secrets
		_ = os.Rename(tmp, p)
	}
}

// ReadStatus reads the status file (tray icon).
func ReadStatus(path string) (Status, error) {
	var s Status
	b, err := os.ReadFile(path) // #nosec G304 -- fixed status file
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}
