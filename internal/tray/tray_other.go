//go:build !windows

// Package tray is the ControlZit icon in the notification area (Windows).
package tray

import "errors"

// Run is not available outside Windows.
func Run(statusPath string, open bool) error {
	return errors.New("the tray icon is only available on Windows")
}
