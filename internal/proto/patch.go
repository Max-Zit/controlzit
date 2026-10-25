package proto

import (
	"regexp"
	"time"
)

// Windows Update. The agent scans for missing updates on its own (every
// patchScanHours) and on request, installs chosen updates in the background
// and reports with TypePatchReport whenever its state changes.
const (
	KindPatchScan    = "patch.scan"
	KindPatchInstall = "patch.install"
	TypePatchReport  = "patch_report" // agent → server
)

// Patch states of an agent.
const (
	PatchIdle       = "idle"
	PatchScanning   = "scanning"
	PatchInstalling = "installing"
)

// PatchUpdate is an update that is not installed.
type PatchUpdate struct {
	ID         string    `json:"id"` // Windows Update identity (GUID)
	Title      string    `json:"title"`
	KB         string    `json:"kb,omitempty"`
	Severity   string    `json:"severity,omitempty"` // MSRC: Critical, Important, Moderate, Low
	Categories []string  `json:"categories,omitempty"`
	Size       int64     `json:"size,omitempty"`
	Reboot     bool      `json:"reboot,omitempty"` // may need a restart
	Published  time.Time `json:"published,omitempty"`
	Downloaded bool      `json:"downloaded,omitempty"`
}

// Security reports whether the update fixes security issues (security and
// critical updates, Defender definitions, or an MSRC severity).
func (u *PatchUpdate) Security() bool {
	if u.Severity != "" {
		return true
	}
	for _, c := range u.Categories {
		switch c {
		case "Security Updates", "Critical Updates", "Definition Updates":
			return true
		}
	}
	return false
}

// Definitions reports whether the update is a definition update (Defender
// signatures), which Windows Update replaces with a new ID several times a day.
func (u *PatchUpdate) Definitions() bool {
	for _, c := range u.Categories {
		if c == "Definition Updates" {
			return true
		}
	}
	return false
}

// Upgrade reports whether the update is a Windows feature upgrade (never
// installed automatically).
func (u *PatchUpdate) Upgrade() bool {
	for _, c := range u.Categories {
		if c == "Upgrades" {
			return true
		}
	}
	return false
}

// PatchHistoryItem is an entry of the Windows Update history.
type PatchHistoryItem struct {
	Title  string    `json:"title"`
	Date   time.Time `json:"date"`
	Result int       `json:"result"` // OperationResultCode: 2 succeeded, 3 with errors, 4 failed, 5 aborted
}

// PatchResult is the outcome of one update of an installation.
type PatchResult struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Result  int    `json:"result"`
	HResult int64  `json:"hresult,omitempty"`
}

// PatchInstallRun is the last installation an agent ran.
type PatchInstallRun struct {
	By             string        `json:"by"`
	Started        time.Time     `json:"started"`
	Finished       time.Time     `json:"finished,omitzero"`
	Requested      int           `json:"requested"`
	Result         int           `json:"result"`
	RebootRequired bool          `json:"reboot_required,omitempty"`
	Rebooting      bool          `json:"rebooting,omitempty"`
	Results        []PatchResult `json:"results,omitempty"`
	Error          string        `json:"error,omitempty"`
}

// PatchReport is the Windows Update state of a device.
type PatchReport struct {
	State          string             `json:"state"`
	ScannedAt      time.Time          `json:"scanned_at,omitzero"`
	ScanError      string             `json:"scan_error,omitempty"`
	Updates        []PatchUpdate      `json:"updates"`
	History        []PatchHistoryItem `json:"history,omitempty"`
	RebootRequired bool               `json:"reboot_required,omitempty"`
	Install        *PatchInstallRun   `json:"install,omitempty"`
}

// PatchInstall asks the agent to install updates.
type PatchInstall struct {
	IDs []string `json:"ids"`
	// Reboot restarts the computer (in five minutes, with a notice) when the
	// installation needs it.
	Reboot bool   `json:"reboot,omitempty"`
	By     string `json:"by"`
}

var (
	guidRE    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	packageRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+._~-]{0,200}$`)
)

// ValidGUID reports whether s is a Windows Update identity.
func ValidGUID(s string) bool { return guidRE.MatchString(s) }

// ValidUpdateID reports whether s names an update: a Windows Update
// identity or a Linux package name.
func ValidUpdateID(s string) bool { return guidRE.MatchString(s) || packageRE.MatchString(s) }

// MaxPatchInstall limits the updates of one installation.
const MaxPatchInstall = 200
