//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/max-zit/rmmzit/internal/agent"
)

// On Linux the agent runs under systemd. "install" copies the program to
// /usr/local/bin, enrolls it (with --code) and starts the service.

const (
	linuxBin  = "/usr/local/bin/rmmzit-agent"
	linuxUnit = "/etc/systemd/system/rmmzit-agent.service"
)

const unitFile = `[Unit]
Description=RMMZit Agent
Documentation=https://maxzit.com
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/rmmzit-agent run
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
`

func isService() bool { return false }

func runService(string) error { return errors.New("systemd runs: rmmzit-agent run") }

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput() // #nosec G204 -- fixed arguments
	if err != nil {
		return fmt.Errorf("systemctl %v: %v: %s", args, err, out)
	}
	return nil
}

func copySelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	if exe == linuxBin {
		return nil
	}
	src, err := os.Open(exe) // #nosec G304 -- this program
	if err != nil {
		return err
	}
	defer src.Close()
	tmp := linuxBin + ".new"
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755) // #nosec G302 G304 -- a program in /usr/local/bin
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, linuxBin)
}

func installService(code string) error {
	if os.Geteuid() != 0 {
		return errors.New("run it as root (sudo)")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("this system has no systemd")
	}
	if err := copySelf(); err != nil {
		return fmt.Errorf("cannot copy the agent to %s: %w", linuxBin, err)
	}
	dir := agent.DefaultDir()
	if code != "" {
		if _, err := agent.LoadConfig(dir); err == nil {
			fmt.Println("Already enrolled; the code is not used (run 'rmmzit-agent enroll --force --code …' to move the device).")
		} else {
			d, err := agent.ParseEnrollCode(code)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			c, err := agent.EnrollWith(ctx, dir, d)
			cancel()
			var refused *agent.RefusedError
			switch {
			case errors.As(err, &refused):
				return err
			case err != nil:
				if perr := agent.SavePending(dir, d); perr != nil {
					return perr
				}
				fmt.Println("The server cannot be reached now; the service will finish the enrollment:", err)
			default:
				fmt.Printf("Enrolled: customer %q, site %q, device #%d.\n", c.Customer, c.Site, c.DeviceID)
			}
		}
	}
	removeLegacyService()
	if err := os.WriteFile(linuxUnit, []byte(unitFile), 0o644); err != nil { // #nosec G306 -- a systemd unit is world-readable
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := systemctl("enable", "--now", "rmmzit-agent.service"); err != nil {
		return err
	}
	if err := systemctl("restart", "rmmzit-agent.service"); err != nil { // a new binary on reinstall
		return err
	}
	fmt.Println("The RMMZit agent is installed and running (systemctl status rmmzit-agent).")
	return nil
}

func uninstallService() error {
	if os.Geteuid() != 0 {
		return errors.New("run it as root (sudo)")
	}
	_ = systemctl("disable", "--now", "rmmzit-agent.service")
	removeLegacyService()
	_ = os.Remove(linuxUnit)
	_ = systemctl("daemon-reload")
	if err := agent.Forget(agent.DefaultDir()); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Println("warning:", err)
	}
	_ = os.Remove(linuxBin)
	fmt.Println("The RMMZit agent is removed.")
	return nil
}

// The service of agents installed before the rename to RMMZit.
const (
	legacyBin  = "/usr/local/bin/controlzit-agent"
	legacyUnit = "/etc/systemd/system/controlzit-agent.service"
)

// migrateLegacyService moves an agent that runs as the old service (it got
// this version by self-update) to the rmmzit-agent service: the program is
// copied to its new place, the new unit written, and a separate systemd job
// stops the old service (this process) and starts the new one.
func migrateLegacyService(log interface{ Info(string, ...any) }) {
	exe, err := os.Executable()
	if err != nil || os.Geteuid() != 0 || os.Getenv("INVOCATION_ID") == "" {
		return
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil || exe != legacyBin {
		return
	}
	if _, err := os.Stat(linuxUnit); err == nil {
		return // already done; the switch is under way
	}
	if copySelf() != nil || os.WriteFile(linuxUnit, []byte(unitFile), 0o644) != nil { // #nosec G306 -- a systemd unit is world-readable
		return
	}
	if systemctl("daemon-reload") != nil {
		return
	}
	log.Info("moving to the rmmzit-agent service (the agent was renamed from ControlZit)")
	script := "systemctl disable --now controlzit-agent.service; rm -f " + legacyUnit + " " + legacyBin +
		"; systemctl daemon-reload; systemctl enable --now rmmzit-agent.service"
	_ = exec.Command("systemd-run", "--no-block", "--unit=rmmzit-agent-migrate", "--collect", "/bin/sh", "-c", script).Run() // #nosec G204 -- fixed command
}

// removeLegacyService removes the old service when the agent is installed
// again under the new name.
func removeLegacyService() {
	if _, err := os.Stat(legacyUnit); err != nil {
		return
	}
	_ = systemctl("disable", "--now", "controlzit-agent.service")
	_ = os.Remove(legacyUnit)
	_ = os.Remove(legacyBin)
	_ = systemctl("daemon-reload")
}
