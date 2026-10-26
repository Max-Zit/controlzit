//go:build windows

package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// killTree makes a cancelled command stop with all the processes it started
// (an installer often hands over to a child process).
func killTree(cmd *exec.Cmd) *exec.Cmd {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		taskkill := filepath.Join(os.Getenv("SystemRoot"), "System32", "taskkill.exe")
		k := exec.Command(taskkill, "/F", "/T", "/PID", strconv.Itoa(cmd.Process.Pid)) // #nosec G204 G702 -- fixed system binary, a process ID
		k.SysProcAttr = hiddenProc
		_ = k.Run()
		return cmd.Process.Kill()
	}
	cmd.WaitDelay = 10 * time.Second
	return cmd
}
