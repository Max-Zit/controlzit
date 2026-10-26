//go:build windows

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/max-zit/controlzit/internal/proto"
)

func init() { register(proto.KindWinget, runWinget) }

// wingetExe finds winget.exe of App Installer (SYSTEM has no WindowsApps
// alias in its path).
func wingetExe() (string, error) {
	dirs, _ := filepath.Glob(filepath.Join(os.Getenv("ProgramFiles"), "WindowsApps", "Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"))
	sort.Sort(sort.Reverse(sort.StringSlice(dirs)))
	for _, d := range dirs {
		exe := filepath.Join(d, "winget.exe")
		if _, err := os.Stat(exe); err == nil { // #nosec G703 -- path under ProgramFiles
			return exe, nil
		}
	}
	if p, err := exec.LookPath("winget.exe"); err == nil {
		return p, nil
	}
	return "", errors.New("winget (App Installer) is not installed on this device")
}

const wingetNoInstaller = 0x8A150010 // no installer for the scope (exit codes are unsigned on Windows)

var wingetCommon = []string{"--source", "winget", "--accept-source-agreements", "--disable-interactivity"}

func validQuery(q string) bool {
	if len(q) < 2 || len(q) > 80 || strings.HasPrefix(q, "-") {
		return false
	}
	for _, r := range q {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func runWinget(ctx context.Context, raw json.RawMessage) (any, error) {
	var a proto.Winget
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	exe, err := wingetExe()
	if err != nil {
		return nil, err
	}
	id := []string{"--id", a.ID, "--exact"}
	quiet := []string{"--silent", "--accept-package-agreements"}
	var argv []string
	table := false
	timeout := 3 * time.Minute
	switch a.Action {
	case proto.WingetUpgrades:
		argv, table = append([]string{"upgrade", "--include-unknown"}, wingetCommon...), true
	case proto.WingetList:
		argv, table = append([]string{"list"}, wingetCommon...), true
	case proto.WingetSearch:
		if !validQuery(a.Query) {
			return nil, errors.New("enter 2 to 80 characters to search for")
		}
		argv, table = append([]string{"search", "--name", a.Query, "--count", "50"}, wingetCommon...), true
	case proto.WingetInstall, proto.WingetUpgrade, proto.WingetUninstall:
		timeout = 25 * time.Minute
		if a.Action == proto.WingetUpgrade && a.ID == proto.WingetAll {
			argv = append(append([]string{"upgrade", "--all", "--include-unknown"}, quiet...), wingetCommon...)
			break
		}
		if !proto.ValidWingetID(a.ID) {
			return nil, errors.New("bad package ID")
		}
		switch a.Action {
		case proto.WingetInstall:
			argv = append(append(append([]string{"install", "--scope", "machine"}, id...), quiet...), wingetCommon...)
		case proto.WingetUpgrade:
			argv = append(append(append([]string{"upgrade"}, id...), quiet...), wingetCommon...)
		default:
			argv = append(append([]string{"uninstall", "--silent"}, id...), wingetCommon...)
		}
	default:
		return nil, errors.New("unknown action")
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, err := wingetRun(cctx, exe, argv)
	if err != nil {
		return nil, err
	}
	// A package without a machine-wide installer: try its default scope.
	if a.Action == proto.WingetInstall && res.ExitCode == wingetNoInstaller {
		argv = append(append(append([]string{"install"}, id...), quiet...), wingetCommon...)
		if res, err = wingetRun(cctx, exe, argv); err != nil {
			return nil, err
		}
	}
	if table {
		res.Packages = parseWingetTable(res.Output)
		res.Output = ""
	} else if len(res.Output) > 4096 {
		res.Output = "…" + res.Output[len(res.Output)-4096:]
	}
	return res, nil
}

func wingetRun(ctx context.Context, exe string, argv []string) (*proto.WingetResult, error) {
	cmd := exec.CommandContext(ctx, exe, argv...) // #nosec G204 -- winget with validated arguments
	cmd.SysProcAttr = hiddenProc
	killTree(cmd)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	res := &proto.WingetResult{Output: decodeOutput(out.Bytes())}
	var ee *exec.ExitError
	switch {
	case ctx.Err() != nil:
		return nil, errors.New("winget did not finish in time")
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	case err != nil:
		return nil, err
	}
	return res, nil
}
