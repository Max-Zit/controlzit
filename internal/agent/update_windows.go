//go:build windows

package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

const packageExt = ".msi"

// startInstaller runs msiexec on its own: it outlives this service, which
// the upgrade stops and replaces.
func startInstaller(msi, logPath string) error {
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "msiexec.exe")
	cmd := exec.Command(exe, "/i", msi, "/qn", "/norestart", "/l*v", logPath) // #nosec G204 -- verified installer in our own directory
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
