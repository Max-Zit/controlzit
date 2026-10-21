//go:build windows

package agent

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// protectDir gives only SYSTEM and Administrators access (no inherited
// "Users: read" from ProgramData). When the agent runs as another user
// (enrolled from an elevated prompt, or a test run), that user keeps access.
func protectDir(dir string) error {
	sddl := "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	if tu, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil && !tu.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		sddl += "(A;OICI;FA;;;" + tu.User.Sid.String() + ")"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

var (
	wtsapi32                       = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformation = wtsapi32.NewProc("WTSQuerySessionInformationW")
	kernel32                       = windows.NewLazySystemDLL("kernel32.dll")
	procGetTickCount64             = kernel32.NewProc("GetTickCount64")
)

const (
	wtsUserName   = 5
	wtsDomainName = 7
)

func wtsString(session uint32, class int) string {
	var buf *uint16
	var n uint32
	r, _, _ := procWTSQuerySessionInformation.Call(0, uintptr(session), uintptr(class), uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n))) // #nosec G103 -- Win32 out-parameters
	if r == 0 || buf == nil {
		return ""
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf))) // #nosec G103 -- memory returned by WTSQuerySessionInformation
	return windows.UTF16PtrToString(buf)
}

// consoleUser is DOMAIN\user of the active console session, or "".
func consoleUser() string {
	id := windows.WTSGetActiveConsoleSessionId()
	if id == 0xFFFFFFFF {
		return ""
	}
	u := wtsString(id, wtsUserName)
	if u == "" {
		return ""
	}
	if d := wtsString(id, wtsDomainName); d != "" {
		return d + `\` + u
	}
	return u
}

func bootTime() time.Time {
	ms, _, _ := procGetTickCount64.Call()
	return time.Now().Add(-time.Duration(ms) * time.Millisecond).Truncate(time.Second).UTC()
}

// basicInfo reads the OS version from the registry (fast; no WMI).
func basicInfo() SysInfo {
	si := SysInfo{OS: "Windows", BootTime: bootTime(), LoggedOnUser: consoleUser()}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return si
	}
	defer k.Close()
	name, _, _ := k.GetStringValue("ProductName")
	build, _, _ := k.GetStringValue("CurrentBuild")
	ubr, _, _ := k.GetIntegerValue("UBR")
	disp, _, _ := k.GetStringValue("DisplayVersion")
	maj, _, err1 := k.GetIntegerValue("CurrentMajorVersionNumber")
	minr, _, _ := k.GetIntegerValue("CurrentMinorVersionNumber")
	ver, _, _ := k.GetStringValue("CurrentVersion")
	if err1 == nil {
		ver = fmt.Sprintf("%d.%d", maj, minr)
	}
	// Windows 11 still says "Windows 10" in ProductName.
	if b := atoi(build); b >= 22000 && strings.HasPrefix(name, "Windows 10") {
		name = "Windows 11" + strings.TrimPrefix(name, "Windows 10")
	}
	if name != "" {
		si.OS = name
		if disp != "" {
			si.OS += " " + disp
		}
	}
	si.OSVersion = ver
	if build != "" {
		si.OSBuild = fmt.Sprintf("%s.%d", build, ubr)
	}
	return si
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// hiddenProc runs PowerShell without a console window.
var hiddenProc = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}

// markEnrolled records the enrollment in the registry, where the MSI looks
// for it (an upgrade then does not ask for a code again).
func markEnrolled(on bool) {
	const path = `SOFTWARE\MaxZit\ControlZit Agent`
	if !on {
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, path)
		return
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.SetStringValue("Enrolled", "1")
}
