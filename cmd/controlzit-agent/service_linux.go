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

	"github.com/max-zit/controlzit/internal/agent"
)

// On Linux the agent runs under systemd. "install" copies the program to
// /usr/local/bin, enrolls it (with --code) and starts the service.

const (
	linuxBin  = "/usr/local/bin/controlzit-agent"
	linuxUnit = "/etc/systemd/system/controlzit-agent.service"
)

const unitFile = `[Unit]
Description=ControlZit Agent
Documentation=https://maxzit.com
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/controlzit-agent run
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
`

func isService() bool { return false }

func runService(string) error { return errors.New("systemd runs: controlzit-agent run") }

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
			fmt.Println("Already enrolled; the code is not used (run 'controlzit-agent enroll --force --code …' to move the device).")
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
	if err := os.WriteFile(linuxUnit, []byte(unitFile), 0o644); err != nil { // #nosec G306 -- a systemd unit is world-readable
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := systemctl("enable", "--now", "controlzit-agent.service"); err != nil {
		return err
	}
	if err := systemctl("restart", "controlzit-agent.service"); err != nil { // a new binary on reinstall
		return err
	}
	fmt.Println("The ControlZit agent is installed and running (systemctl status controlzit-agent).")
	return nil
}

func uninstallService() error {
	if os.Geteuid() != 0 {
		return errors.New("run it as root (sudo)")
	}
	_ = systemctl("disable", "--now", "controlzit-agent.service")
	_ = os.Remove(linuxUnit)
	_ = systemctl("daemon-reload")
	if err := agent.Forget(agent.DefaultDir()); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Println("warning:", err)
	}
	_ = os.Remove(linuxBin)
	fmt.Println("The ControlZit agent is removed.")
	return nil
}
