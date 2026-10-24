//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const packageExt = ""

// startInstaller replaces this program with the verified download and
// exits; systemd (Restart=always) starts the new version.
func startInstaller(bin, _ string) error {
	if err := os.Chmod(bin, 0o755); err != nil { // #nosec G302 -- a program
		return err
	}
	// The new program must run on this machine.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "version").Output() // #nosec G204 -- the verified download
	if err != nil || !strings.HasPrefix(string(out), "controlzit-agent ") {
		return fmt.Errorf("the new agent does not start here: %v %s", err, strings.TrimSpace(string(out)))
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	// Copy next to the running program, then rename over it (same file system).
	tmp := exe + ".new"
	src, err := os.Open(bin) // #nosec G304 -- the verified download
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755) // #nosec G302 G304 -- a program next to this one
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Remove(tmp)
		return errors.New("cannot replace the agent: " + err.Error())
	}
	// Let the result reach the server, then restart through systemd.
	time.AfterFunc(3*time.Second, func() { os.Exit(0) })
	return nil
}
