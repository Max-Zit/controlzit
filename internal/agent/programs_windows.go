//go:build windows

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/max-zit/controlzit/internal/proto"
)

// Installed programs from the uninstall entries in the registry, and their
// silent removal. winget runs an uninstaller as it is registered, without
// a silent switch: an NSIS uninstaller (Winamp) then waits for a click on
// the invisible SYSTEM desktop while winget reports success. So the agent
// picks the silent way itself and reports success only when the entry is
// gone.

func init() {
	register(proto.KindPrograms, func(context.Context, json.RawMessage) (any, error) {
		return listPrograms(), nil
	})
	register(proto.KindUninstall, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a proto.Uninstall
		if err := args(raw, &a); err != nil {
			return nil, err
		}
		if !proto.ValidProgramKey(a.Key) {
			return nil, errors.New("bad program key")
		}
		return uninstallProgram(ctx, a.Key)
	})
}

const uninstallPath = `Software\Microsoft\Windows\CurrentVersion\Uninstall`

// arpView is one place with uninstall entries.
type arpView struct {
	id   string // HKLM64, HKLM32, HKU:<sid>
	root registry.Key
	path string
	wow  uint32
	user string
}

func arpViews() []arpView {
	v := []arpView{
		{id: "HKLM64", root: registry.LOCAL_MACHINE, path: uninstallPath, wow: registry.WOW64_64KEY},
		{id: "HKLM32", root: registry.LOCAL_MACHINE, path: uninstallPath, wow: registry.WOW64_32KEY},
	}
	// The registry of every signed-in user (programs installed per user).
	if k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS); err == nil {
		sids, _ := k.ReadSubKeyNames(-1)
		_ = k.Close()
		for _, sid := range sids {
			if !strings.HasPrefix(sid, "S-1-5-21-") || strings.HasSuffix(sid, "_Classes") {
				continue
			}
			v = append(v, arpView{id: "HKU:" + sid, root: registry.USERS, path: sid + `\` + uninstallPath, wow: registry.WOW64_64KEY, user: accountName(sid)})
		}
	}
	return v
}

func accountName(sid string) string {
	s, err := windows.StringToSid(sid)
	if err != nil {
		return sid
	}
	acc, dom, _, err := s.LookupAccount("")
	if err != nil {
		return sid
	}
	if dom != "" {
		return dom + `\` + acc
	}
	return acc
}

func regString(k registry.Key, name string) string {
	s, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

func regDword(k registry.Key, name string) uint64 {
	n, _, _ := k.GetIntegerValue(name)
	return n
}

func listPrograms() *proto.ProgramsResult {
	res := &proto.ProgramsResult{Programs: []proto.Program{}}
	seen := map[string]bool{}
	for _, v := range arpViews() {
		k, err := registry.OpenKey(v.root, v.path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|v.wow)
		if err != nil {
			continue
		}
		names, _ := k.ReadSubKeyNames(-1)
		_ = k.Close()
		for _, name := range names {
			e, err := registry.OpenKey(v.root, v.path+`\`+name, registry.QUERY_VALUE|v.wow)
			if err != nil {
				continue
			}
			p := proto.Program{
				Key: v.id + ":" + name, Name: regString(e, "DisplayName"), Version: regString(e, "DisplayVersion"),
				Publisher: regString(e, "Publisher"), User: v.user,
			}
			hidden := p.Name == "" || regDword(e, "SystemComponent") == 1 || regString(e, "ParentKeyName") != ""
			if !hidden {
				p.Silent = silentMethod(e, name) != ""
			}
			_ = e.Close()
			// The same program can be in both registry views.
			dup := p.Name + "|" + p.Version + "|" + p.User
			if hidden || seen[dup] || !proto.ValidProgramKey(p.Key) {
				continue
			}
			seen[dup] = true
			res.Programs = append(res.Programs, p)
		}
	}
	sort.Slice(res.Programs, func(i, j int) bool {
		return strings.ToLower(res.Programs[i].Name) < strings.ToLower(res.Programs[j].Name)
	})
	return res
}

var msiCodeRE = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

// silentMethod names how the program can be removed without questions:
// msi, quiet (its own silent command), inno or nsis; "" when it cannot.
func silentMethod(e registry.Key, name string) string {
	switch {
	case regDword(e, "WindowsInstaller") == 1 && msiCodeRE.MatchString(name):
		return "msi"
	case regString(e, "QuietUninstallString") != "":
		return "quiet"
	}
	exe, _ := splitCommand(regString(e, "UninstallString"))
	if exe == "" {
		return ""
	}
	if _, _, err := e.GetStringValue("Inno Setup: App Path"); err == nil {
		return "inno"
	}
	if isNSIS(exe) {
		return "nsis"
	}
	return ""
}

// splitCommand splits a registered command line into the program and the
// rest; uninstall strings are often unquoted paths with spaces.
func splitCommand(cmd string) (exe, rest string) {
	cmd = strings.TrimSpace(cmd)
	if strings.HasPrefix(cmd, `"`) {
		if i := strings.Index(cmd[1:], `"`); i >= 0 {
			return cmd[1 : i+1], strings.TrimSpace(cmd[i+2:])
		}
		return "", ""
	}
	if i := strings.Index(strings.ToLower(cmd), ".exe"); i >= 0 {
		return cmd[:i+4], strings.TrimSpace(cmd[i+4:])
	}
	return "", ""
}

// isNSIS reports whether the uninstaller was made with NSIS (Nullsoft).
func isNSIS(exe string) bool {
	f, err := os.Open(exe) // #nosec G304 -- the registered uninstaller
	if err != nil {
		return false
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, 4<<20))
	return bytes.Contains(b, []byte("Nullsoft"))
}

func uninstallProgram(ctx context.Context, key string) (*proto.UninstallResult, error) {
	var view *arpView
	for _, v := range arpViews() {
		if strings.HasPrefix(key, v.id+":") {
			view = &v
			break
		}
	}
	if view == nil {
		return nil, errors.New("this user is not signed in anymore; refresh the list")
	}
	name := strings.TrimPrefix(key, view.id+":")
	path := view.path + `\` + name
	e, err := registry.OpenKey(view.root, path, registry.QUERY_VALUE|view.wow)
	if err != nil {
		return nil, errors.New("the program is not installed anymore; refresh the list")
	}
	res := &proto.UninstallResult{Name: regString(e, "DisplayName"), Method: silentMethod(e, name)}
	quiet, plain := regString(e, "QuietUninstallString"), regString(e, "UninstallString")
	_ = e.Close()

	var exe, rest string
	switch res.Method {
	case "msi":
		exe, rest = filepath.Join(os.Getenv("SystemRoot"), "System32", "msiexec.exe"), "/x "+name+" /qn /norestart"
	case "quiet":
		exe, rest = splitCommand(quiet)
	case "inno":
		exe, rest = splitCommand(plain)
		rest += " /VERYSILENT /SUPPRESSMSGBOXES /NORESTART"
	case "nsis":
		exe, rest = splitCommand(plain)
		rest += " /S"
	default:
		return nil, errors.New("this program has no silent uninstaller; remove it on the computer or with a script")
	}
	if exe == "" {
		return nil, errors.New("this program has no silent uninstaller; remove it on the computer or with a script")
	}
	if !filepath.IsAbs(exe) {
		if p, err := exec.LookPath(exe); err == nil {
			exe = p
		}
	}
	start := time.Now()
	cctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, exe) // #nosec G204 G702 -- the program's own registered uninstaller
	// The registered command line as it is (quoting rules of the uninstaller).
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW, CmdLine: syscall.EscapeArg(exe) + " " + strings.TrimSpace(rest)}
	err = cmd.Run()
	var ee *exec.ExitError
	switch {
	case cctx.Err() != nil:
		return nil, errors.New("the uninstaller did not finish in 20 minutes")
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	case err != nil:
		return nil, fmt.Errorf("cannot start the uninstaller: %v", err)
	}
	// NSIS and others hand over to a copy of themselves and return at once:
	// wait until the entry is gone.
	wait := time.Minute
	if res.Method == "nsis" || res.Method == "inno" {
		wait = 10 * time.Minute
	}
	// The console waits 27 minutes for the answer.
	deadline := time.Now().Add(wait)
	if limit := start.Add(25 * time.Minute); deadline.After(limit) {
		deadline = limit
	}
	for {
		k, err := registry.OpenKey(view.root, path, registry.QUERY_VALUE|view.wow)
		if err != nil {
			return res, nil
		}
		_ = k.Close()
		if time.Now().After(deadline) || ctx.Err() != nil {
			return nil, errors.New("the uninstaller ended, but the program is still installed")
		}
		time.Sleep(2 * time.Second)
	}
}
