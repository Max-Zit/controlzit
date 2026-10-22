//go:build !windows && !linux

package main

import "errors"

func isService() bool { return false }

func runService(string) error { return errors.New("not supported on this system") }

func installService(string) error {
	return errors.New("use the system service manager (a systemd unit comes with the Linux agent)")
}

func uninstallService() error { return installService("") }
