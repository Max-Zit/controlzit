//go:build linux

package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/sys/unix"

	"github.com/max-zit/controlzit/internal/proto"
)

// A terminal is a login shell of root on a pseudo-terminal. The agent runs
// as root already, so it needs no helper process: it connects the stream
// itself and copies between the stream and the terminal.

func init() {
	register(proto.KindTermStart, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a proto.TermStart
		if err := args(raw, &a); err != nil {
			return nil, err
		}
		if a.Session == "" || a.Token == "" || len(a.Session) > 64 || len(a.Technician) > 120 || !proto.ValidTermSize(a.Cols, a.Rows) {
			return nil, errors.New("bad terminal request")
		}
		ws, err := dialStream(ctx, helperDir, a.Session, a.Token)
		if err != nil {
			return nil, err
		}
		if err := startTerminal(ws, a); err != nil {
			_ = ws.Close(websocket.StatusInternalError, "")
			return nil, fmt.Errorf("cannot start the shell: %w", err)
		}
		return nil, nil
	})
}

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

func startTerminal(ws *websocket.Conn, a proto.TermStart) error {
	master, slave, err := openPTY()
	if err != nil {
		return err
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
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "CONTROLZIT_TECHNICIAN=" + a.Technician}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		_ = master.Close()
		_ = slave.Close()
		return err
	}
	_ = slave.Close()
	if self != nil {
		self.Log.Info("terminal session started", "session", a.Session, "technician", a.Technician)
	}
	go serveTerminal(ws, master, cmd, a.Session)
	return nil
}

func serveTerminal(ws *websocket.Conn, master *os.File, cmd *exec.Cmd, session string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exited := make(chan int, 1)
	go func() {
		err := cmd.Wait()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		exited <- code
	}()
	// shell → browser
	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		buf := make([]byte, 32<<10)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
				werr := ws.Write(wctx, websocket.MessageBinary, buf[:n])
				wcancel()
				if werr != nil {
					cancel()
					return
				}
			}
			if err != nil {
				return // EIO once the shell and its children are gone
			}
		}
	}()
	// browser → shell
	go func() {
		for {
			typ, data, err := ws.Read(ctx)
			if err != nil {
				cancel()
				return
			}
			if typ != websocket.MessageText {
				continue
			}
			var in proto.TermInput
			if json.Unmarshal(data, &in) != nil {
				continue
			}
			switch in.T {
			case "i":
				if _, err := master.Write([]byte(in.D)); err != nil {
					cancel()
					return
				}
			case "r":
				if proto.ValidTermSize(in.Cols, in.Rows) {
					setSize(master, in.Cols, in.Rows)
				}
			}
		}
	}()
	code := -1
	select {
	case code = <-exited:
		// Let the last output through, then say so.
		select {
		case <-outDone:
		case <-time.After(time.Second):
		}
		wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
		_ = ws.Write(wctx, websocket.MessageText, []byte(`{"t":"exit","code":`+strconv.Itoa(code)+`}`))
		wcancel()
		_ = ws.Close(websocket.StatusNormalClosure, "")
	case <-ctx.Done():
		// The technician left: hang up the shell and what it started.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGHUP)
		select {
		case code = <-exited:
		case <-time.After(3 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			code = <-exited
		}
		_ = ws.CloseNow()
	}
	_ = master.Close()
	if self != nil {
		self.Log.Info("terminal session ended", "session", session, "exit", code)
	}
}
