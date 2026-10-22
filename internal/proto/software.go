package proto

import "regexp"

// Software with winget (Windows Package Manager) as SYSTEM, machine scope,
// from the winget community source only.
const KindWinget = "sw.winget"

// Winget actions.
const (
	WingetUpgrades  = "upgrades"  // packages with a newer version
	WingetList      = "list"      // installed packages winget knows
	WingetSearch    = "search"    // by name
	WingetInstall   = "install"   // ID
	WingetUpgrade   = "upgrade"   // ID, or WingetAll
	WingetUninstall = "uninstall" // ID
	WingetAll       = "--all"
)

// Winget is the argument of sw.winget.
type Winget struct {
	Action string `json:"action"`
	ID     string `json:"id,omitempty"`
	Query  string `json:"query,omitempty"`
}

// WingetPackage is a row of a winget table.
type WingetPackage struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	Version   string `json:"version,omitempty"`
	Available string `json:"available,omitempty"`
}

// WingetResult is the answer of sw.winget.
type WingetResult struct {
	Packages []WingetPackage `json:"packages,omitempty"`
	ExitCode int             `json:"exit_code"`
	Output   string          `json:"output,omitempty"` // end of the output (install, upgrade, uninstall)
}

var wingetIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_\-]{0,127}$`)

// ValidWingetID reports whether s looks like a winget package ID.
func ValidWingetID(s string) bool { return wingetIDRE.MatchString(s) }
