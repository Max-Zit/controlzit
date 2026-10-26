//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
)

// Chocolatey (community repository) as SYSTEM. The console offers it only
// when an administrator switched it on; the client is installed through
// winget (Chocolatey.Chocolatey, an MSI) the first time it is needed.

func init() { register(proto.KindChoco, runChoco) }

func chocoExe() string {
	root := os.Getenv("ChocolateyInstall")
	if root == "" {
		root = filepath.Join(os.Getenv("ProgramData"), "chocolatey")
	}
	return filepath.Join(root, "bin", "choco.exe")
}

// ensureChoco installs the Chocolatey client if it is missing.
func ensureChoco(ctx context.Context) (string, error) {
	exe := chocoExe()
	if _, err := os.Stat(exe); err == nil { // #nosec G703 -- path under ProgramData
		return exe, nil
	}
	w, err := wingetExe()
	if err != nil {
		return "", errors.New("the Chocolatey client is not installed, and winget is missing to install it")
	}
	argv := append([]string{"install", "--id", "Chocolatey.Chocolatey", "--exact", "--scope", "machine", "--silent", "--accept-package-agreements"}, wingetCommon...)
	res, err := wingetRun(ctx, w, argv)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(exe); err != nil { // #nosec G703 -- path under ProgramData
		return "", errors.New("the Chocolatey client could not be installed: " + trim(res.Output, 300))
	}
	return exe, nil
}

func runChoco(ctx context.Context, raw json.RawMessage) (any, error) {
	var a proto.Choco
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	var argv []string
	timeout := 3 * time.Minute
	common := []string{"-y", "--no-progress", "--no-color"}
	switch a.Action {
	case proto.ChocoSearch:
		if !validQuery(a.Query) {
			return nil, errors.New("enter 2 to 80 characters to search for")
		}
		argv = []string{"search", a.Query, "--limit-output", "--page-size", "50", "--no-color"}
	case proto.ChocoOutdated:
		argv = []string{"outdated", "--limit-output", "--no-color"}
	case proto.ChocoInstall, proto.ChocoUpgrade:
		timeout = 25 * time.Minute
		id := a.ID
		if a.Action == proto.ChocoUpgrade && id == proto.WingetAll {
			id = "all"
		} else if !proto.ValidChocoID(id) {
			return nil, errors.New("bad package ID")
		}
		argv = append([]string{a.Action, id}, common...)
	default:
		return nil, errors.New("unknown action")
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	exe := chocoExe()
	if _, err := os.Stat(exe); err != nil { // #nosec G703 -- path under ProgramData
		if a.Action == proto.ChocoOutdated {
			return &proto.WingetResult{}, nil // nothing installed through Chocolatey yet
		}
		if exe, err = ensureChoco(cctx); err != nil {
			return nil, err
		}
	}
	res, err := wingetRun(cctx, exe, argv)
	if err != nil {
		return nil, err
	}
	switch a.Action {
	case proto.ChocoSearch, proto.ChocoOutdated:
		res.Packages = parseChoco(res.Output, a.Action == proto.ChocoOutdated)
		res.Output = ""
	default:
		if res.ExitCode == 1641 || res.ExitCode == 3010 {
			res.ExitCode = 0 // done, a restart completes it
		}
		res.Output = tail(res.Output, 4096)
	}
	return res, nil
}
