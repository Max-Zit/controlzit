//go:build linux

package agent

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/max-zit/rmmzit/internal/proto"
)

// openPTY opens a new pseudo-terminal: the master (non-blocking, so a
// close ends a pending read) and its slave.
func openPTY() (*os.File, *os.File, error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		_ = unix.Close(fd)
		return nil, nil, err
	}
	n, err := unix.IoctlGetUint32(fd, unix.TIOCGPTN)
	if err != nil {
		_ = unix.Close(fd)
		return nil, nil, err
	}
	master := os.NewFile(uintptr(fd), "/dev/ptmx")
	slave, err := os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(n), 10), os.O_RDWR|unix.O_NOCTTY, 0) // #nosec G304 -- the pty just opened
	if err != nil {
		_ = master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}

func setSize(master *os.File, cols, rows int) {
	rc, err := master.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Col: uint16(cols), Row: uint16(rows)}) // #nosec G115 -- checked by ValidTermSize
	})
}

// rootShell is root's login shell from /etc/passwd, else bash or sh.
func rootShell() string {
	if f, err := os.Open("/etc/passwd"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			p := strings.Split(sc.Text(), ":")
			if len(p) == 7 && p[2] == "0" && p[6] != "" {
				if _, err := os.Stat(p[6]); err == nil && !strings.HasSuffix(p[6], "nologin") && !strings.HasSuffix(p[6], "false") {
					return p[6]
				}
			}
		}
	}
	for _, s := range []string{"/bin/bash", "/usr/bin/bash", "/bin/sh"} {
		if _, err := os.Stat(s); err == nil {
			return s
		}
	}
	return "/bin/sh"
}

// ptyShell is root's login shell on a pseudo-terminal.
type ptyShell struct {
	master *os.File
	cmd    *exec.Cmd
}

func startTerminal(a proto.TermStart) (terminal, error) {
	master, slave, err := openPTY()
	if err != nil {
		return nil, err
	}
	setSize(master, a.Cols, a.Rows)
	shell := rootShell()
	cmd := exec.Command(shell)                      // #nosec G204 -- root's login shell
	cmd.Args = []string{"-" + filepath.Base(shell)} // a login shell
	cmd.Dir = "/root"
	if _, err := os.Stat(cmd.Dir); err != nil {
		cmd.Dir = "/"
	}
	lang := os.Getenv("LANG")
	if lang == "" {
		lang = "C.UTF-8"
	}
	cmd.Env = []string{"TERM=xterm-256color", "COLORTERM=truecolor", "HOME=" + cmd.Dir, "USER=root", "LOGNAME=root", "SHELL=" + shell, "LANG=" + lang,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "RMMZIT_TECHNICIAN=" + a.Technician}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		_ = master.Close()
		_ = slave.Close()
		return nil, err
	}
	_ = slave.Close()
	return &ptyShell{master: master, cmd: cmd}, nil
}

func (p *ptyShell) Read(b []byte) (int, error)  { return p.master.Read(b) } // EIO once the shell and its children are gone
func (p *ptyShell) Write(b []byte) (int, error) { return p.master.Write(b) }
func (p *ptyShell) Resize(cols, rows int)       { setSize(p.master, cols, rows) }
func (p *ptyShell) Hangup()                     { _ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGHUP) }
func (p *ptyShell) Kill()                       { _ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL) }
func (p *ptyShell) Close()                      { _ = p.master.Close() }

func (p *ptyShell) Wait() int {
	var ee *exec.ExitError
	if err := p.cmd.Wait(); errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 0
}
