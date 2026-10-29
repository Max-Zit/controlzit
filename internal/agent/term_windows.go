//go:build windows

package agent

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/max-zit/controlzit/internal/proto"
)

// On Windows the terminal is Windows PowerShell as SYSTEM on a pseudo
// console (ConPTY, Windows 10 1809 / Server 2019 and later), which turns the
// console into the same VT stream as on Linux. The shell and everything it
// starts run in a job object, so leaving the session ends them all.

type conShell struct {
	pc      windows.Handle // pseudo console
	in, out *os.File       // our ends of its input and output pipes
	process windows.Handle
	job     windows.Handle
	once    sync.Once
}

func startTerminal(a proto.TermStart) (terminal, error) {
	var inR, inW, outR, outW windows.Handle
	if err := windows.CreatePipe(&inR, &inW, nil, 0); err != nil {
		return nil, err
	}
	if err := windows.CreatePipe(&outR, &outW, nil, 0); err != nil {
		_ = windows.CloseHandle(inR)
		_ = windows.CloseHandle(inW)
		return nil, err
	}
	var pc windows.Handle
	err := windows.CreatePseudoConsole(windows.Coord{X: int16(a.Cols), Y: int16(a.Rows)}, inR, outW, 0, &pc) // #nosec G115 -- checked by ValidTermSize
	// The pseudo console holds its own copies of these ends.
	_ = windows.CloseHandle(inR)
	_ = windows.CloseHandle(outW)
	if err != nil {
		_ = windows.CloseHandle(inW)
		_ = windows.CloseHandle(outR)
		return nil, errors.New("this Windows has no pseudo console (Windows 10 1809 or Server 2019 and later are needed)")
	}
	t := &conShell{pc: pc, in: os.NewFile(uintptr(inW), "conpty-in"), out: os.NewFile(uintptr(outR), "conpty-out")}
	if err := t.start(a.Technician); err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

func (t *conShell) start(technician string) error {
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return err
	}
	defer attrs.Delete()
	// The attribute takes the handle value itself as its "pointer".
	pcValue := *(*unsafe.Pointer)(unsafe.Pointer(&t.pc)) // #nosec G103 -- reinterprets the handle, see above
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, pcValue, unsafe.Sizeof(t.pc)); err != nil {
		return err
	}
	sys := os.Getenv("SystemRoot")
	if sys == "" {
		sys = `C:\Windows`
	}
	shell := filepath.Join(sys, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	cmdline, err := windows.UTF16PtrFromString(`"` + shell + `" -NoLogo`)
	if err != nil {
		return err
	}
	dir := os.Getenv("SystemDrive") + `\`
	if dir == `\` {
		dir = `C:\`
	}
	dirp, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	env := envBlock(append(os.Environ(), "CONTROLZIT_TECHNICIAN="+technician))
	si := windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	si.Cb = uint32(unsafe.Sizeof(si)) // #nosec G103 -- the size the API asks for
	// Empty standard handles: without them the shell would write to the
	// agent's own handles instead of the pseudo console.
	si.Flags = windows.STARTF_USESTDHANDLES
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(nil, cmdline, nil, nil, false, windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT,
		&env[0], dirp, &si.StartupInfo, &pi); err != nil {
		return err
	}
	_ = windows.CloseHandle(pi.Thread)
	t.process = pi.Process
	// Everything the shell starts ends with the job.
	if job, err := windows.CreateJobObject(nil, nil); err == nil {
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err == nil { // #nosec G103 -- the API takes the struct's address
			if windows.AssignProcessToJobObject(job, pi.Process) == nil {
				t.job = job
			}
		}
		if t.job == 0 {
			_ = windows.CloseHandle(job)
		}
	}
	return nil
}

// envBlock writes an environment block (sorted, NUL-separated, UTF-16).
func envBlock(env []string) []uint16 {
	sort.Slice(env, func(i, j int) bool { return strings.ToUpper(env[i]) < strings.ToUpper(env[j]) })
	var b []uint16
	for _, kv := range env {
		if strings.IndexByte(kv, 0) >= 0 {
			continue
		}
		u, err := windows.UTF16FromString(kv)
		if err != nil {
			continue
		}
		b = append(b, u...) // ends with its NUL
	}
	return append(b, 0)
}

func (t *conShell) Read(p []byte) (int, error)  { return t.out.Read(p) }
func (t *conShell) Write(p []byte) (int, error) { return t.in.Write(p) }

func (t *conShell) Resize(cols, rows int) {
	_ = windows.ResizePseudoConsole(t.pc, windows.Coord{X: int16(cols), Y: int16(rows)}) // #nosec G115 -- checked by ValidTermSize
}

func (t *conShell) Wait() int {
	if t.process == 0 {
		return -1
	}
	_, _ = windows.WaitForSingleObject(t.process, windows.INFINITE)
	var code uint32
	if windows.GetExitCodeProcess(t.process, &code) != nil {
		return -1
	}
	return int(code) // #nosec G115 -- exit codes are shown as they are
}

// Hangup and Kill end the shell with everything in its job.
func (t *conShell) Hangup() { t.Kill() }

func (t *conShell) Kill() {
	switch {
	case t.job != 0:
		_ = windows.TerminateJobObject(t.job, 1)
	case t.process != 0:
		_ = windows.TerminateProcess(t.process, 1)
	}
}

func (t *conShell) Close() {
	t.once.Do(func() {
		// Closing the pseudo console can wait until its output is read.
		go func() { _, _ = io.Copy(io.Discard, t.out) }()
		windows.ClosePseudoConsole(t.pc)
		_ = t.in.Close()
		_ = t.out.Close()
		if t.job != 0 {
			_ = windows.CloseHandle(t.job)
		}
		if t.process != 0 {
			_ = windows.CloseHandle(t.process)
		}
	})
}
