//go:build linux

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
)

// Remote actions on Linux: systemd services, processes from /proc, power
// with shutdown(8), and scripts with bash or sh as root.

func init() {
	register(proto.KindSvcList, func(ctx context.Context, _ json.RawMessage) (any, error) { return listUnits(ctx) })
	register(proto.KindSvcCtl, controlUnit)
	register(proto.KindProcList, func(context.Context, json.RawMessage) (any, error) { return listProcs() })
	register(proto.KindProcKill, killProc)
	register(proto.KindPower, powerLinux)
	register(proto.KindScriptRun, runShellScript)
}

// ---- services

func listUnits(ctx context.Context) ([]proto.Service, error) {
	if !have("systemctl") {
		return nil, errors.New("this system has no systemd")
	}
	out, err := exec.CommandContext(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager").Output() // #nosec G204 -- fixed command
	if err != nil {
		return nil, err
	}
	enabled := map[string]string{}
	if fo, err := exec.CommandContext(ctx, "systemctl", "list-unit-files", "--type=service", "--no-legend", "--plain", "--no-pager").Output(); err == nil { // #nosec G204 -- fixed command
		for _, l := range strings.Split(string(fo), "\n") {
			if f := strings.Fields(l); len(f) >= 2 {
				enabled[f[0]] = f[1]
			}
		}
	}
	var list []proto.Service
	for _, l := range strings.Split(string(out), "\n") {
		// unit load active sub description…
		f := strings.Fields(l)
		if len(f) < 4 || !strings.HasSuffix(f[0], ".service") || f[1] == "not-found" {
			continue
		}
		st := map[string]string{"running": "running", "dead": "stopped", "exited": "stopped", "failed": "stopped", "start": "starting", "stop": "stopping"}[f[3]]
		if st == "" {
			st = f[3]
		}
		start := map[string]string{"enabled": "automatic", "static": "manual", "disabled": "disabled", "masked": "disabled", "indirect": "manual"}[enabled[f[0]]]
		if start == "" {
			start = "manual"
		}
		list = append(list, proto.Service{Name: strings.TrimSuffix(f[0], ".service"), Display: strings.Join(f[4:], " "), State: st, StartType: start})
	}
	sort.Slice(list, func(i, j int) bool { return strings.ToLower(list[i].Display) < strings.ToLower(list[j].Display) })
	return list, nil
}

func controlUnit(ctx context.Context, raw json.RawMessage) (any, error) {
	var a proto.SvcControl
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	if a.Name == "" || strings.HasPrefix(a.Name, "-") || strings.ContainsAny(a.Name, " /\x00") || len(a.Name) > 200 {
		return nil, errors.New("no such service")
	}
	if (a.Name == "rmmzit-agent" || a.Name == "controlzit-agent") && a.Action != "start" {
		return nil, errors.New("the RMMZit agent cannot stop itself from the console")
	}
	switch a.Action {
	case "start", "stop", "restart":
	default:
		return nil, errors.New("unknown action")
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "systemctl", a.Action, "--", a.Name+".service").CombinedOutput() // #nosec G204 -- validated unit name
	if err != nil {
		return nil, fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil, nil
}

// ---- processes

func listProcs() ([]proto.Process, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	page := uint64(os.Getpagesize()) // #nosec G115 -- page size is positive
	var out []proto.Process
	for _, e := range ents {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		stat, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat")) // #nosec G304 -- /proc entries
		if err != nil {
			continue
		}
		// pid (comm) state ppid … ; comm may contain spaces and parentheses.
		s := string(stat)
		open, close := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
		if open < 0 || close < open {
			continue
		}
		f := strings.Fields(s[close+1:])
		if len(f) < 22 {
			continue
		}
		p := proto.Process{PID: uint32(pid), Name: s[open+1 : close]}
		ppid, _ := strconv.ParseUint(f[1], 10, 32)
		threads, _ := strconv.ParseUint(f[17], 10, 32)
		rss, _ := strconv.ParseUint(f[21], 10, 64)
		p.PPID, p.Threads, p.Memory = uint32(ppid), uint32(threads), rss*page // #nosec G115 -- values from /proc fit
		sid, _ := strconv.ParseUint(f[3], 10, 32)
		p.Session = uint32(sid) // #nosec G115 -- session ID from /proc
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Memory > out[j].Memory })
	return out, nil
}

func killProc(ctx context.Context, raw json.RawMessage) (any, error) {
	var a proto.ProcKill
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	if a.PID <= 1 || int(a.PID) == os.Getpid() {
		return nil, errors.New("this process cannot be ended from the console")
	}
	b, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(a.PID), 10) + "/stat")
	if err != nil {
		return nil, errors.New("the process is no longer running")
	}
	s := string(b)
	name := s[strings.IndexByte(s, '(')+1 : strings.LastIndexByte(s, ')')]
	if name != a.Name {
		return nil, errors.New("the process has changed; refresh the list")
	}
	if name == "systemd" || name == "init" || name == "kthreadd" || name == "rmmzit-agent" || name == "controlzit-agen" {
		return nil, errors.New("this process cannot be ended from the console")
	}
	if err := syscall.Kill(int(a.PID), syscall.SIGTERM); err != nil {
		return nil, err
	}
	// Give it five seconds to end, then force it.
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if _, err := os.Stat("/proc/" + strconv.FormatUint(uint64(a.PID), 10)); err != nil {
			return nil, nil
		}
	}
	return nil, syscall.Kill(int(a.PID), syscall.SIGKILL)
}

// ---- power

func powerLinux(ctx context.Context, raw json.RawMessage) (any, error) {
	var a proto.Power
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	if a.Delay < 0 || a.Delay > 3600 || len(a.Message) > 500 {
		return nil, errors.New("bad delay or message")
	}
	when := "now"
	if a.Delay > 0 {
		when = "+" + strconv.Itoa((a.Delay+59)/60) // shutdown counts minutes
	}
	var argv []string
	switch a.Action {
	case "restart":
		argv = []string{"-r", when}
	case "shutdown":
		argv = []string{"-h", when}
	case "cancel":
		argv = []string{"-c"}
	default:
		return nil, errors.New("unknown action")
	}
	if a.Message != "" && a.Action != "cancel" {
		argv = append(argv, strings.NewReplacer("\r", " ", "\n", " ").Replace(a.Message))
	}
	out, err := exec.CommandContext(ctx, "shutdown", argv...).CombinedOutput() // #nosec G204 -- fixed command, validated arguments
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil, nil
}

// ---- scripts

func runShellScript(ctx context.Context, raw json.RawMessage) (any, error) {
	var a proto.ScriptRun
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	if a.Script == "" || len(a.Script) > proto.MaxScriptSize {
		return nil, errors.New("the script is empty or too long")
	}
	if a.Timeout < 5 || a.Timeout > 3600 {
		return nil, errors.New("the timeout must be 5–3600 seconds")
	}
	shell := "/bin/sh"
	switch a.Shell {
	case "bash":
		shell = "/bin/bash"
	case "sh":
	default:
		return nil, errors.New("this device runs bash or sh scripts")
	}
	dir := filepath.Join(helperDir, "scripts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, "run-*.sh")
	if err != nil {
		return nil, err
	}
	name := f.Name()
	defer os.Remove(name)
	_, werr := f.WriteString(a.Script + "\n")
	if cerr := f.Close(); werr != nil || cerr != nil {
		return nil, errors.New("cannot write the script file")
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(a.Timeout)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, shell, name) // #nosec G204 -- our own temp file
	cmd.Env = append(os.Environ(), "LANG=C.UTF-8")
	cmd.Dir = "/"
	killTree(cmd)
	out := &capWriter{max: proto.MaxScriptOutput}
	cmd.Stdout, cmd.Stderr = out, out
	start := time.Now()
	err = cmd.Run()
	res := proto.ScriptResult{Output: out.buf.String(), Truncated: out.truncated, Duration: time.Since(start).Round(time.Millisecond)}
	var ee *exec.ExitError
	switch {
	case cctx.Err() == context.DeadlineExceeded:
		res.TimedOut, res.ExitCode = true, -1
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	case err != nil:
		return nil, err
	}
	return res, nil
}

// capWriter keeps the first max bytes.
type capWriter struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := w.max - w.buf.Len(); room > 0 {
		if len(p) > room {
			w.buf.Write(p[:room])
			w.truncated = true
		} else {
			w.buf.Write(p)
		}
	} else if len(p) > 0 {
		w.truncated = true
	}
	return len(p), nil
}

// processList is the process list for the monitors.
func processList() ([]proto.Process, error) { return listProcs() }

// countEvents: Linux has no Windows event logs.
func countEvents(context.Context, proto.EventMonitor) (int, error) {
	return 0, errors.New("event logs are watched on Windows only")
}
