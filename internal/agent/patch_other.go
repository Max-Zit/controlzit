//go:build !windows && !linux

package agent

import (
	"context"
	"errors"
	"time"
)

var errNoPatches = errors.New("updates are only managed on Windows")

func patchScan(context.Context) (*PatchScanResult, error) { return nil, errNoPatches }

func patchInstall(context.Context, []string) (*PatchInstallResult, error) { return nil, errNoPatches }

func scheduleRestart(time.Duration, string) error { return errNoPatches }
