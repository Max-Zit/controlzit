//go:build windows

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
	"time"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/max-zit/controlzit/internal/proto"
)

func init() {
	register(proto.KindSvcList, func(ctx context.Context, _ json.RawMessage) (any, error) { return listServices() })
	register(proto.KindSvcCtl, controlService)
	register(proto.KindProcList, func(ctx context.Context, _ json.RawMessage) (any, error) { return listProcesses() })
	register(proto.KindProcKill, killProcess)
	register(proto.KindPower, power)
	register(proto.KindScriptRun, runScript)
}

// ---- services

var stateNames = map[svc.State]string{svc.Stopped: "stopped", svc.StartPending: "starting", svc.StopPending: "stopping",
	svc.Running: "running", svc.ContinuePending: "continuing", svc.PausePending: "pausing", svc.Paused: "paused"}

var startNames = map[uint32]string{mgr.StartAutomatic: "automatic", mgr.StartManual: "manual", mgr.StartDisabled: "disabled", 0: "boot", 1: "system"}

func listServices() ([]proto.Service, error) {
	// Read-only access: listing needs no control rights.
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, err
	}
	m := &mgr.Mgr{Handle: h}
	defer m.Disconnect()
	names, err := m.ListServices()
	if err != nil {
		return nil, err
	}
	out := make([]proto.Service, 0, len(names))
	for _, n := range names {
		n16, _ := windows.UTF16PtrFromString(n)
		sh, err := windows.OpenService(h, n16, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
		if err != nil {
			continue
		}
		s := &mgr.Service{Name: n, Handle: sh}
		cfg, err1 := s.Config()
		st, err2 := s.Query()
		s.Close()
		if err1 != nil || err2 != nil {
			continue
		}
		if cfg.ServiceType&(windows.SERVICE_KERNEL_DRIVER|windows.SERVICE_FILE_SYSTEM_DRIVER) != 0 {
			continue // drivers are not managed here
		}
		start := startNames[cfg.StartType]
		if cfg.StartType == mgr.StartAutomatic && cfg.DelayedAutoStart {
			start = "automatic (delayed)"
		}
		out = append(out, proto.Service{Name: n, Display: cfg.DisplayName, State: stateNames[st.State], StartType: start, PID: st.ProcessId})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Display) < strings.ToLower(out[j].Display) })
	return out, nil
}

func waitState(s *mgr.Service, want svc.State, d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the service is still %s", stateNames[st.State])
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func controlService(ctx context.Context, raw json.RawMessage) (any, error) {
	var a proto.SvcControl
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	if strings.EqualFold(a.Name, "ControlZitAgent") && a.Action != "start" {
		return nil, errors.New("the ControlZit agent cannot stop itself from the console")
	}
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()
	s, err := m.OpenService(a.Name)
	if err != nil {
		return nil, errors.New("no such service")
	}
	defer s.Close()
	stop := func() error {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Stopped {
			return nil
		}
		if _, err := s.Control(svc.Stop); err != nil {
			return err
		}
		return waitState(s, svc.Stopped, 60*time.Second)
	}
	start := func() error {
		if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return err
		}
		return waitState(s, svc.Running, 60*time.Second)
	}
	switch a.Action {
	case "start":
		err = start()
	case "stop":
		err = stop()
	case "restart":
		if err = stop(); err == nil {
			err = start()
		}
	default:
		return nil, errors.New("unknown action")
	}
	return nil, err
}

// ---- processes

var (
	psapi                    = windows.NewLazySystemDLL("psapi.dll")
	procGetProcessMemoryInfo = psapi.NewProc("GetProcessMemoryInfo")
)

type processMemoryCounters struct {
	Cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func workingSet(pid uint32) uint64 {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(h)
	var c processMemoryCounters
	c.Cb = uint32(unsafe.Sizeof(c))
	if r, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&c)), uintptr(c.Cb)); r == 0 { // #nosec G103 -- Win32 struct
		return 0
	}
	return uint64(c.WorkingSetSize)
}

func listProcesses() ([]proto.Process, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var out []proto.Process
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		p := proto.Process{PID: e.ProcessID, PPID: e.ParentProcessID, Name: windows.UTF16ToString(e.ExeFile[:]), Threads: e.Threads}
		_ = windows.ProcessIdToSessionId(e.ProcessID, &p.Session)
		p.Memory = workingSet(e.ProcessID)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Memory > out[j].Memory })
	return out, nil
}

// criticalProcesses end Windows when killed (blue screen or logoff of all).
var criticalProcesses = map[string]bool{"system": true, "smss.exe": true, "csrss.exe": true, "wininit.exe": true, "winlogon.exe": true,
	"services.exe": true, "lsass.exe": true, "lsaiso.exe": true, "registry": true, "memory compression": true}

func killProcess(ctx context.Context, raw json.RawMessage) (any, error) {
	var a proto.ProcKill
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	if a.PID <= 4 || a.PID == uint32(os.Getpid()) || criticalProcesses[strings.ToLower(a.Name)] { // #nosec G115 -- PIDs fit
		return nil, errors.New("this process cannot be ended from the console")
	}
	procs, err := listProcesses()
	if err != nil {
		return nil, err
	}
	found := false
	for _, p := range procs {
		if p.PID == a.PID {
			if !strings.EqualFold(p.Name, a.Name) {
				return nil, errors.New("the process has changed; refresh the list")
			}
			if criticalProcesses[strings.ToLower(p.Name)] || strings.EqualFold(p.Name, "controlzit-agent.exe") {
				return nil, errors.New("this process cannot be ended from the console")
			}
			found = true
		}
	}
	if !found {
		return nil, errors.New("the process is no longer running")
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, a.PID)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	return nil, windows.TerminateProcess(h, 1)
}

// ---- power

func power(ctx context.Context, raw json.RawMessage) (any, error) {
	var a proto.Power
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	if a.Delay < 0 || a.Delay > 3600 || len(a.Message) > 500 {
		return nil, errors.New("bad delay or message")
	}
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "shutdown.exe")
	var argv []string
	switch a.Action {
	case "restart":
		argv = []string{"/r", "/t", strconv.Itoa(a.Delay), "/d", "p:0:0"}
	case "shutdown":
		argv = []string{"/s", "/t", strconv.Itoa(a.Delay), "/d", "p:0:0"}
	case "cancel":
		argv = []string{"/a"}
	default:
		return nil, errors.New("unknown action")
	}
	if a.Message != "" && a.Action != "cancel" {
		argv = append(argv, "/c", strings.NewReplacer("\r", " ", "\n", " ", "\"", "'").Replace(a.Message))
	}
	out, err := exec.CommandContext(ctx, exe, argv...).CombinedOutput() // #nosec G204 -- fixed system binary, validated arguments
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil, nil
}

// ---- scripts

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

func runScript(ctx context.Context, raw json.RawMessage) (any, error) {
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
	cctx, cancel := context.WithTimeout(ctx, time.Duration(a.Timeout)*time.Second)
	defer cancel()
	// The script goes to a file of our own: PowerShell given the script on
	// the command line serializes errors and progress as CLIXML.
	var ext, body string
	switch a.Shell {
	case "powershell":
		ext, body = ".ps1", utf8BOM+strings.ReplaceAll(a.Script, "\n", "\r\n")+"\r\n" // BOM: Windows PowerShell reads it as UTF-8
	case "cmd":
		ext, body = ".cmd", "@echo off\r\nchcp 65001 >nul\r\n"+strings.ReplaceAll(a.Script, "\n", "\r\n")+"\r\n"
	default:
		return nil, errors.New("unknown shell")
	}
	dir := filepath.Join(helperDir, "scripts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, "run-*"+ext)
	if err != nil {
		return nil, err
	}
	name := f.Name()
	defer os.Remove(name)
	_, werr := f.WriteString(body)
	if cerr := f.Close(); werr != nil || cerr != nil {
		return nil, errors.New("cannot write the script file")
	}
	var cmd *exec.Cmd
	if a.Shell == "powershell" {
		// A service has no console, so PowerShell would write in the ANSI
		// code page; write every stream as UTF-8 text ourselves.
		run := "$w = New-Object IO.StreamWriter([Console]::OpenStandardOutput(), (New-Object Text.UTF8Encoding $false)); " +
			"try { & '" + strings.ReplaceAll(name, "'", "''") + "' *>&1 | Out-String -Stream -Width 250 | ForEach-Object { $w.WriteLine($_) } } finally { $w.Flush() }; exit $LASTEXITCODE"
		cmd = exec.CommandContext(cctx, powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", run) // #nosec G204 -- our own temp file
	} else {
		cmd = exec.CommandContext(cctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/d", "/c", name) // #nosec G204 -- our own temp file
	}
	cmd.SysProcAttr = hiddenProc
	out := &capWriter{max: proto.MaxScriptOutput}
	cmd.Stdout, cmd.Stderr = out, out
	start := time.Now()
	err = cmd.Run()
	res := proto.ScriptResult{Output: decodeOutput(out.buf.Bytes()), Truncated: out.truncated, Duration: time.Since(start).Round(time.Millisecond)}
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

// utf8BOM makes Windows PowerShell 5.1 read a script file as UTF-8.
var utf8BOM = string([]byte{0xEF, 0xBB, 0xBF})

var procMultiByteToWideChar = windows.NewLazySystemDLL("kernel32.dll").NewProc("MultiByteToWideChar")

// decodeOutput reads script output: UTF-8 when it is valid, else the OEM
// code page that console programs use without a console of their own.
func decodeOutput(b []byte) string {
	if utf8.Valid(b) || len(b) == 0 {
		return string(b)
	}
	const cpOEM = 1
	n, _, _ := procMultiByteToWideChar.Call(cpOEM, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, 0) // #nosec G103 -- Win32 buffer
	if n == 0 {
		return strings.ToValidUTF8(string(b), "?")
	}
	w := make([]uint16, n)
	_, _, _ = procMultiByteToWideChar.Call(cpOEM, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&w[0])), n) // #nosec G103 -- Win32 buffer
	return windows.UTF16ToString(w)
}
