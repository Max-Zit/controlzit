//go:build windows

package agent

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/max-zit/rmmzit/internal/proto"
)

// startHelper launches "rmmzit-agent rdhelper" in the console session.
// As SYSTEM (the service) it uses a copy of its own token moved to that
// session, so the helper can also capture the sign-in screen and UAC
// prompts; otherwise (a test run as a user) it starts a normal child.
func startHelper(dir string, a proto.RDStart) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	argv := []string{exe, "rdhelper", "--dir", dir, "--session", a.Session, "--technician", a.Technician}
	if a.NoNotice {
		argv = append(argv, "--no-notice")
	}
	if a.NoClipboard {
		argv = append(argv, "--no-clipboard")
	}
	if !isSystem() {
		cmd := exec.Command(exe, argv[1:]...) // #nosec G204 -- our own executable
		cmd.Stdin = strings.NewReader(a.Token + "\n")
		cmd.SysProcAttr = hiddenProc
		if err := cmd.Start(); err != nil {
			return err
		}
		go func() { _ = cmd.Wait() }()
		return nil
	}
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xFFFFFFFF {
		return errors.New("no console session")
	}
	var self windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ALL_ACCESS, &self); err != nil {
		return err
	}
	defer self.Close()
	var tok windows.Token
	if err := windows.DuplicateTokenEx(self, windows.MAXIMUM_ALLOWED, nil, windows.SecurityIdentification, windows.TokenPrimary, &tok); err != nil {
		return err
	}
	defer tok.Close()
	if err := windows.SetTokenInformation(tok, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), uint32(unsafe.Sizeof(session))); err != nil { // #nosec G103 -- Win32 in-parameter
		return err
	}
	// The token goes through a pipe on stdin, not the command line.
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	defer r.Close()
	if err := windows.SetHandleInformation(windows.Handle(r.Fd()), windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
		_ = w.Close()
		return err
	}
	desk, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := windows.StartupInfo{Desktop: desk, Flags: windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW, StdInput: windows.Handle(r.Fd()), ShowWindow: windows.SW_HIDE}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	cmdline := windows.ComposeCommandLine(argv)
	cl, _ := windows.UTF16PtrFromString(cmdline)
	exe16, _ := windows.UTF16PtrFromString(exe)
	err = windows.CreateProcessAsUser(tok, exe16, cl, nil, nil, true, windows.CREATE_NO_WINDOW|windows.CREATE_UNICODE_ENVIRONMENT, nil, nil, &si, &pi)
	if err != nil {
		_ = w.Close()
		return err
	}
	_ = windows.CloseHandle(pi.Thread)
	_ = windows.CloseHandle(pi.Process)
	_, err = w.Write([]byte(a.Token + "\n"))
	_ = w.Close()
	return err
}

// isSystem reports whether the process runs as LocalSystem.
func isSystem() bool {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && tu.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

// StartTray starts rmmzit-tray.exe (next to the agent) for the user
// signed in at the console, so the icon appears right after installation.
// Later sign-ins start it from the Run key. It is a no-op when nobody is
// signed in or the icon already runs in that session.
func StartTray() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	tray := filepath.Join(filepath.Dir(exe), "rmmzit-tray.exe")
	if _, err := os.Stat(tray); err != nil {
		return nil // not installed (test runs)
	}
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xFFFFFFFF {
		return nil
	}
	var tok windows.Token
	if err := windows.WTSQueryUserToken(session, &tok); err != nil {
		return nil // nobody signed in
	}
	defer tok.Close()
	desk, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := windows.StartupInfo{Desktop: desk}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	cl, _ := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{tray}))
	app, _ := windows.UTF16PtrFromString(tray)
	// The user's own environment (LOCALAPPDATA, TEMP …), not the service's.
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, tok, false); err == nil {
		defer func() { _ = windows.DestroyEnvironmentBlock(env) }()
	}
	if err := windows.CreateProcessAsUser(tok, app, cl, nil, nil, false, windows.CREATE_UNICODE_ENVIRONMENT, env, nil, &si, &pi); err != nil {
		return err
	}
	_ = windows.CloseHandle(pi.Thread)
	_ = windows.CloseHandle(pi.Process)
	return nil
}
