//go:build linux

package agent

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
)

// Remote desktop on Linux works with X11 desktops. The service finds the
// running X server (its display and the -auth cookie file) and starts the
// helper with them. A Wayland desktop does not let a background program
// read the screen or send input, so the request ends with a message.

type xServer struct {
	display, auth string
	uid           int
}

// graphicalSession is the active local desktop session (loginctl):
// its type (x11, wayland) and display.
func graphicalSession() (typ, display string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "loginctl", "list-sessions", "--no-legend").Output()
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		props, err := exec.CommandContext(ctx, "loginctl", "show-session", f[0], "-p", "Type", "-p", "Active", "-p", "Remote", "-p", "Display").Output() // #nosec G204 -- a session id from loginctl
		if err != nil {
			continue
		}
		p := parseProps(string(props))
		if p["Active"] == "yes" && p["Remote"] != "yes" && (p["Type"] == "x11" || p["Type"] == "wayland" || p["Type"] == "mir") {
			return p["Type"], p["Display"]
		}
	}
	return "", ""
}

func parseProps(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			m[k] = v
		}
	}
	return m
}

// xServers lists the running X servers from /proc (Xwayland is not one).
func xServers() []xServer {
	var list []xServer
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		raw, err := os.ReadFile(filepath.Join(d, "cmdline")) // #nosec G304 -- /proc
		if err != nil || len(raw) == 0 {
			continue
		}
		if s, ok := parseXServer(strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")); ok {
			if fi, err := os.Stat(d); err == nil {
				if st, ok := fi.Sys().(*syscall.Stat_t); ok {
					s.uid = int(st.Uid)
				}
			}
			list = append(list, s)
		}
	}
	return list
}

func parseXServer(argv []string) (xServer, bool) {
	switch filepath.Base(argv[0]) {
	case "Xorg", "X", "Xvfb", "Xorg.bin":
	default:
		return xServer{}, false
	}
	s := xServer{display: ":0"}
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case strings.HasPrefix(a, ":") && len(a) > 1:
			s.display = a
		case a == "-auth" && i+1 < len(argv):
			s.auth = argv[i+1]
			i++
		}
	}
	return s, true
}

// findX picks the X server of the active session (or the only one).
func findX() (xServer, error) {
	typ, display := graphicalSession()
	servers := xServers()
	if typ == "wayland" || typ == "mir" {
		return xServer{}, errWayland
	}
	for _, s := range servers {
		if display == "" || s.display == display {
			return s, nil
		}
	}
	if len(servers) > 0 {
		return servers[0], nil
	}
	return xServer{}, errNoX
}

func startHelper(dir string, a proto.RDStart) error {
	x, err := findX()
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"rdhelper", "--dir", dir, "--session", a.Session, "--technician", a.Technician}
	if a.NoNotice {
		args = append(args, "--no-notice")
	}
	cmd := exec.Command(exe, args...) // #nosec G204 -- our own executable
	env := []string{"DISPLAY=" + x.display, "HOME=/root", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "CZ_XSERVER_UID=" + strconv.Itoa(x.uid)}
	if x.auth != "" {
		env = append(env, "XAUTHORITY="+x.auth)
	} else {
		env = append(env, "XAUTHORITY=/nonexistent")
	}
	cmd.Env = env
	cmd.Stdin = bytes.NewReader([]byte(a.Token + "\n"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
