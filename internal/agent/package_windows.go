//go:build windows

package agent

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"

	"github.com/max-zit/controlzit/internal/proto"
)

// Software library: the agent downloads an installer of the server's
// library (hash and command line come in the signed command), runs it
// silently as SYSTEM and reports its exit code.

const packageLimit = 25 * time.Minute // the console waits 27 minutes

func init() {
	register(proto.KindPackageInstall, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p proto.PackageInstall
		if err := args(raw, &p); err != nil {
			return nil, err
		}
		if !p.Valid() {
			return nil, errors.New("bad package")
		}
		if self == nil {
			return nil, errors.New("the agent is not running")
		}
		return self.installPackage(ctx, p)
	})
}

func (a *Agent) installPackage(ctx context.Context, p proto.PackageInstall) (*proto.PackageResult, error) {
	want, _ := hex.DecodeString(p.SHA256)
	dir := filepath.Join(a.Dir, "packages", p.SHA256[:16])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithTimeout(ctx, packageLimit)
	defer cancel()
	file := filepath.Join(dir, p.FileName)
	if err := a.fetchVerified(ctx, proto.PathLibrary+"?sha256="+p.SHA256, file, p.Size, want, packageLimit); err != nil {
		return nil, err
	}
	exe, cmdline := file, syscall.EscapeArg(file)
	logFile := filepath.Join(dir, "install.log")
	if p.Kind == "msi" {
		exe = filepath.Join(os.Getenv("SystemRoot"), "System32", "msiexec.exe")
		cmdline = syscall.EscapeArg(exe) + " /i " + syscall.EscapeArg(file) + " /l*v " + syscall.EscapeArg(logFile)
	}
	if p.Args != "" {
		cmdline += " " + p.Args
	}
	cmd := exec.CommandContext(ctx, exe) // #nosec G204 G702 -- installer and arguments from the signed command
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW, CmdLine: cmdline}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	res := &proto.PackageResult{}
	var ee *exec.ExitError
	switch {
	case ctx.Err() != nil:
		return nil, errors.New("the installer did not finish in 25 minutes")
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	case err != nil:
		return nil, fmt.Errorf("cannot start the installer: %v", err)
	}
	ok := p.Success
	if len(ok) == 0 {
		ok = []int{0, 1641, 3010}
	}
	res.OK = slices.Contains(ok, res.ExitCode)
	res.Reboot = res.ExitCode == 1641 || res.ExitCode == 3010
	res.Output = decodeOutput(out.Bytes())
	if b, err := os.ReadFile(logFile); err == nil { // #nosec G304 -- our own log file
		res.Output = tail(msiLog(b), 8<<10)
	} else {
		res.Output = tail(res.Output, 8<<10)
	}
	return res, nil
}

// msiLog decodes a Windows Installer log (UTF-16 with a BOM, or ANSI).
func msiLog(b []byte) string {
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		u := make([]uint16, 0, len(b)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
		}
		return string(utf16.Decode(u))
	}
	return decodeOutput(b)
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[len(s)-n:]
	for len(s) > 0 && s[0]&0xC0 == 0x80 {
		s = s[1:]
	}
	return "…" + s
}
