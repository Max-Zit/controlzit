package proto

import (
	"regexp"
	"strings"
)

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

// Software library: an installer from the server, installed silently.
const (
	KindPackageInstall = "sw.package"
	PathLibrary        = "/agent/v1/library" // ?sha256=<hex>, the installer of a library package
	MaxLibraryPackage  = 2 << 30
)

// PackageInstall is the argument of sw.package (signed, so the hash and the
// command line are what the console sent).
type PackageInstall struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	FileName string `json:"file_name"`
	Kind     string `json:"kind"` // msi or exe
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Args     string `json:"args,omitempty"`
	Success  []int  `json:"success,omitempty"` // exit codes that mean success (default 0, 1641, 3010)
}

// PackageResult is the answer of sw.package.
type PackageResult struct {
	ExitCode int    `json:"exit_code"`
	OK       bool   `json:"ok"`
	Reboot   bool   `json:"reboot,omitempty"` // 1641 or 3010: a restart completes it
	Output   string `json:"output,omitempty"` // end of the Windows Installer log
}

var (
	sha256RE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	fileNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()+\-]{0,150}\.(msi|exe)$`)
)

// Valid checks a package install before it is signed or run.
func (p *PackageInstall) Valid() bool {
	if !sha256RE.MatchString(p.SHA256) || !fileNameRE.MatchString(p.FileName) || p.Size <= 0 || p.Size > MaxLibraryPackage ||
		(p.Kind != "msi" && p.Kind != "exe") || !ValidArgs(p.Args) || len(p.Name) > 200 || len(p.Success) > 20 {
		return false
	}
	return strings.HasSuffix(strings.ToLower(p.FileName), "."+p.Kind)
}

// ValidArgs reports whether s can be the arguments of an installer: one
// line, no control characters.
func ValidArgs(s string) bool {
	if len(s) > 1000 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// ValidSHA256 reports whether s is a lower-case hex SHA-256.
func ValidSHA256(s string) bool { return sha256RE.MatchString(s) }

// Chocolatey (community repository), optional; the agent installs the
// Chocolatey client through winget when it is needed.
const KindChoco = "sw.choco"

// Chocolatey actions.
const (
	ChocoSearch   = "search"
	ChocoOutdated = "outdated"
	ChocoInstall  = "install"
	ChocoUpgrade  = "upgrade" // ID, or WingetAll
)

// Choco is the argument of sw.choco; the answer is a WingetResult.
type Choco struct {
	Action string `json:"action"`
	ID     string `json:"id,omitempty"`
	Query  string `json:"query,omitempty"`
}

var chocoIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._\-]{0,99}$`)

// ValidChocoID reports whether s looks like a Chocolatey package ID.
func ValidChocoID(s string) bool { return chocoIDRE.MatchString(s) }
