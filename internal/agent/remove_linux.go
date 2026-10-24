//go:build linux

package agent

import (
	"os"
	"os/exec"
	"path/filepath"
)

func installedService() bool { return os.Geteuid() == 0 && os.Getenv("INVOCATION_ID") != "" }

// startUninstall runs "controlzit-agent uninstall" as its own systemd unit:
// it stops this service, so it must not be part of it.
func startUninstall() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	return exec.Command("systemd-run", "--no-block", "--unit=controlzit-agent-remove", "--collect", exe, "uninstall").Run() // #nosec G204 -- this program
}
