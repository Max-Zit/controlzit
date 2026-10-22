//go:build linux

package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
)

// Linux updates through the package manager: apt (Debian, Ubuntu) or dnf
// (Fedora, RHEL and rebuilds). Package names are the update IDs.

func pkgEnv(cmd *exec.Cmd) *exec.Cmd {
	cmd.Env = append(os.Environ(), "LANG=C", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive")
	return cmd
}

func runOut(ctx context.Context, name string, args ...string) (string, int, error) {
	cmd := pkgEnv(exec.CommandContext(ctx, name, args...)) // #nosec G204 -- package manager with validated names
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out.String(), ee.ExitCode(), nil
	}
	if ctx.Err() != nil {
		return out.String(), -1, errors.New("the package manager did not finish in time")
	}
	return out.String(), 0, err
}

func patchScan(ctx context.Context) (*PatchScanResult, error) {
	switch {
	case have("apt-get"):
		return aptScan(ctx)
	case have("dnf"):
		return dnfScan(ctx)
	}
	return nil, errors.New("no supported package manager (apt or dnf)")
}

func aptScan(ctx context.Context) (*PatchScanResult, error) {
	if out, code, err := runOut(ctx, "apt-get", "update", "-q"); err != nil || code != 0 {
		return nil, fmt.Errorf("apt-get update failed: %s", lastLines(out, 3))
	}
	out, _, err := runOut(ctx, "apt", "list", "--upgradable")
	if err != nil {
		return nil, err
	}
	r := &PatchScanResult{RebootRequired: rebootRequired(), History: aptHistory()}
	for _, l := range strings.Split(out, "\n") {
		// name/suite1,suite2 newversion arch [upgradable from: oldversion]
		f := strings.Fields(l)
		if len(f) < 3 || !strings.Contains(f[0], "/") || !strings.Contains(l, "upgradable from") {
			continue
		}
		name, suites, _ := strings.Cut(f[0], "/")
		old := strings.TrimSuffix(l[strings.LastIndex(l, "from: ")+6:], "]")
		u := proto.PatchUpdate{ID: name, Title: name + " " + strings.TrimSpace(old) + " → " + f[1], Categories: []string{"Updates"}}
		if strings.Contains(suites, "-security") {
			u.Categories = []string{"Security Updates"}
		}
		if strings.HasPrefix(name, "linux-image") || strings.HasPrefix(name, "linux-firmware") || name == "systemd" || strings.HasPrefix(name, "libc6") {
			u.Reboot = true
		}
		if proto.ValidUpdateID(u.ID) {
			r.Updates = append(r.Updates, u)
		}
	}
	return r, nil
}

// aptHistory reads the last upgrades from /var/log/apt/history.log.
func aptHistory() []proto.PatchHistoryItem {
	f, err := os.Open("/var/log/apt/history.log")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []proto.PatchHistoryItem
	var at time.Time
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64<<10), 4<<20)
	for s.Scan() {
		l := s.Text()
		if v, ok := strings.CutPrefix(l, "Start-Date: "); ok {
			at, _ = time.ParseInLocation("2006-01-02  15:04:05", strings.TrimSpace(v), time.Local)
		}
		v, ok := strings.CutPrefix(l, "Upgrade: ")
		if !ok {
			continue
		}
		// pkg:arch (old, new), pkg:arch (old, new)
		for _, part := range strings.Split(v, "), ") {
			name, vers, _ := strings.Cut(part, " (")
			name, _, _ = strings.Cut(name, ":")
			vers = strings.TrimSuffix(vers, ")")
			out = append(out, proto.PatchHistoryItem{Title: name + " " + strings.ReplaceAll(vers, ", ", " → "), Date: at.UTC(), Result: 2})
		}
	}
	// newest first, at most 40
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

func dnfScan(ctx context.Context) (*PatchScanResult, error) {
	out, code, err := runOut(ctx, "dnf", "-q", "check-update")
	if err != nil || (code != 0 && code != 100) {
		return nil, fmt.Errorf("dnf check-update failed: %s", lastLines(out, 3))
	}
	sec := map[string]bool{}
	if so, c, err := runOut(ctx, "dnf", "-q", "updateinfo", "list", "--security"); err == nil && c == 0 {
		for _, l := range strings.Split(so, "\n") {
			if f := strings.Fields(l); len(f) >= 3 {
				sec[f[len(f)-1]] = true // name-version-release.arch
			}
		}
	}
	r := &PatchScanResult{RebootRequired: dnfNeedsReboot(ctx)}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) != 3 || !strings.Contains(f[0], ".") {
			continue
		}
		name := f[0][:strings.LastIndex(f[0], ".")]
		arch := f[0][strings.LastIndex(f[0], ".")+1:]
		u := proto.PatchUpdate{ID: name, Title: name + " → " + f[1], Categories: []string{"Updates"}}
		if sec[name+"-"+f[1]+"."+arch] {
			u.Categories = []string{"Security Updates"}
		}
		if strings.HasPrefix(name, "kernel") || name == "glibc" || name == "systemd" {
			u.Reboot = true
		}
		if proto.ValidUpdateID(u.ID) {
			r.Updates = append(r.Updates, u)
		}
	}
	return r, nil
}

func dnfNeedsReboot(ctx context.Context) bool {
	if !have("needs-restarting") {
		return false
	}
	_, code, err := runOut(ctx, "needs-restarting", "-r")
	return err == nil && code == 1
}

func patchInstall(ctx context.Context, ids []string) (*PatchInstallResult, error) {
	for _, id := range ids {
		if !proto.ValidUpdateID(id) || strings.HasPrefix(id, "-") {
			return nil, errors.New("bad package name")
		}
	}
	var out string
	var code int
	var err error
	switch {
	case have("apt-get"):
		args := append([]string{"install", "--only-upgrade", "-y", "-q", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "--"}, ids...)
		out, code, err = runOut(ctx, "apt-get", args...)
	case have("dnf"):
		out, code, err = runOut(ctx, "dnf", append([]string{"-y", "upgrade", "--"}, ids...)...)
	default:
		return nil, errors.New("no supported package manager (apt or dnf)")
	}
	if err != nil {
		return nil, err
	}
	res := &PatchInstallResult{Result: 2, RebootRequired: rebootRequired()}
	result := 2
	if code != 0 {
		res.Result, result = 4, 4
	}
	for _, id := range ids {
		res.Results = append(res.Results, proto.PatchResult{ID: id, Title: id, Result: result})
	}
	if code != 0 {
		return res, fmt.Errorf("the package manager ended with code %d: %s", code, lastLines(out, 4))
	}
	return res, nil
}

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, " / ")
}

// scheduleRestart restarts Linux after d with a wall message.
func scheduleRestart(d time.Duration, msg string) error {
	out, err := exec.Command("shutdown", "-r", "+"+strconv.Itoa(max(1, int(d.Minutes()))), msg).CombinedOutput() // #nosec G204 -- fixed command and text
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
