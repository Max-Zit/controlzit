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

// Installed programs of Windows (the uninstall entries in the registry, for
// the machine and for every signed-in user), and their silent removal.
const (
	KindPrograms  = "sw.programs"
	KindUninstall = "sw.uninstall"
)

// Program is one installed program.
type Program struct {
	Key       string `json:"key"` // ProgramKey: where its uninstall entry is
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Publisher string `json:"publisher,omitempty"`
	User      string `json:"user,omitempty"`   // installed for this user only
	Silent    bool   `json:"silent,omitempty"` // can be removed without questions
}

// ProgramsResult is the answer of sw.programs.
type ProgramsResult struct {
	Programs []Program `json:"programs"`
}

// Uninstall is the argument of sw.uninstall.
type Uninstall struct {
	Key string `json:"key"`
}

// UninstallResult is the answer of sw.uninstall; the program is gone when
// there is no error.
type UninstallResult struct {
	Name     string `json:"name"`
	Method   string `json:"method"` // msi, quiet, inno, nsis
	ExitCode int    `json:"exit_code"`
}

// A program key: the registry view, then the name of the uninstall entry.
// HKLM64:Name, HKLM32:Name or HKU:<user SID>:Name.
var programKeyRE = regexp.MustCompile(`^(HKLM64|HKLM32|HKU:S-1-5-21(-[0-9]{1,10}){1,6}):[^\\/\x00-\x1f]{1,200}$`)

// ValidProgramKey reports whether s is a program key.
func ValidProgramKey(s string) bool { return programKeyRE.MatchString(s) }
