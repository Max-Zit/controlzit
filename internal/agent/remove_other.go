//go:build !windows && !linux

package agent

import "errors"

func installedService() bool { return false }

func startUninstall() error { return errors.New("not supported on this system") }
