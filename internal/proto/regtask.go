package proto

import (
	"errors"
	"strings"
)

// Registry editor and scheduled tasks (Windows, agents 0.12+).
const (
	KindRegList   = "reg.list"
	KindRegSet    = "reg.set"
	KindRegDelete = "reg.delete"
	KindRegNewKey = "reg.newkey"
	KindTaskList  = "task.list"
	KindTaskCtl   = "task.control"
)

// RegRoots are the root keys the editor opens (HKEY_CURRENT_USER of the
// agent would be SYSTEM's own; the users' hives are under HKU).
var RegRoots = []string{"HKLM", "HKU", "HKCR", "HKCC"}

// RegValueTypes are the value types the editor writes.
var RegValueTypes = []string{"REG_SZ", "REG_EXPAND_SZ", "REG_DWORD", "REG_QWORD", "REG_MULTI_SZ"}

// RegPath is a key, e.g. HKLM\SOFTWARE\MaxZit.
type RegPath struct {
	Path string `json:"path"`
}

// RegKey is the content of a key.
type RegKey struct {
	Path    string     `json:"path"`
	Subkeys []string   `json:"subkeys"`
	Values  []RegValue `json:"values"`
	More    bool       `json:"more,omitempty"` // lists were cut
}

// RegValue is a value as text: strings as they are, numbers in decimal,
// REG_MULTI_SZ one string per line, binary as hex.
type RegValue struct {
	Name string `json:"name"` // "" is the default value
	Type string `json:"type"`
	Data string `json:"data"`
}

// RegSet writes a value.
type RegSet struct {
	Path string `json:"path"`
	RegValue
}

// RegDelete deletes a value, or (Key) the key Path with all it holds.
type RegDelete struct {
	Path string `json:"path"`
	Name string `json:"name,omitempty"`
	Key  bool   `json:"key,omitempty"`
}

// RegNewKey creates the key Path\Name.
type RegNewKey struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

// CleanRegPath checks and normalises a registry path: a known root, no
// empty parts, at most 255 characters per part and 32 parts.
func CleanRegPath(p string) (string, error) {
	p = strings.Trim(strings.TrimSpace(strings.ReplaceAll(p, "/", `\`)), `\`)
	parts := strings.Split(p, `\`)
	root := strings.ToUpper(parts[0])
	switch root {
	case "HKEY_LOCAL_MACHINE":
		root = "HKLM"
	case "HKEY_USERS":
		root = "HKU"
	case "HKEY_CLASSES_ROOT":
		root = "HKCR"
	case "HKEY_CURRENT_CONFIG":
		root = "HKCC"
	}
	known := false
	for _, r := range RegRoots {
		known = known || r == root
	}
	if !known {
		return "", errors.New("unknown registry root (HKLM, HKU, HKCR or HKCC)")
	}
	parts[0] = root
	if len(parts) > 32 {
		return "", errors.New("registry path too long")
	}
	for _, s := range parts[1:] {
		if s == "" || len(s) > 255 || strings.ContainsAny(s, "\x00\r\n") {
			return "", errors.New("bad registry path")
		}
	}
	return strings.Join(parts, `\`), nil
}

// ProtectedRegKey reports whether a key must not be deleted: a root, a
// key right below a root, or one of the system's own branches.
func ProtectedRegKey(path string) bool {
	parts := strings.Split(path, `\`)
	if len(parts) <= 2 {
		return true
	}
	up := strings.ToUpper(path)
	for _, p := range []string{`HKLM\SYSTEM\CURRENTCONTROLSET`, `HKLM\SYSTEM\CONTROLSET001`, `HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION`,
		`HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION`, `HKLM\SOFTWARE\POLICIES`, `HKLM\SOFTWARE\CLASSES`, `HKLM\SOFTWARE\WOW6432NODE`} {
		if up == p {
			return true
		}
	}
	return false
}

// SchedTask is a scheduled task.
type SchedTask struct {
	Path       string `json:"path"` // folder, e.g. \ or \Vendor\
	Name       string `json:"name"`
	State      string `json:"state"` // Ready, Running, Disabled, Queued, Unknown
	LastRun    string `json:"last_run,omitempty"`
	LastResult int64  `json:"last_result"`
	NextRun    string `json:"next_run,omitempty"`
	Author     string `json:"author,omitempty"`
	RunAs      string `json:"run_as,omitempty"`
	Action     string `json:"action,omitempty"` // the first action's command line
}

// TaskList asks for the tasks; All includes Windows' own (\Microsoft\…).
type TaskList struct {
	All bool `json:"all,omitempty"`
}

// TaskControl runs, ends, enables, disables or deletes a task.
type TaskControl struct {
	Path   string `json:"path"`
	Name   string `json:"name"`
	Action string `json:"action"` // run, end, enable, disable, delete
}

// ValidTaskControl checks a task control request.
func ValidTaskControl(t TaskControl) error {
	switch t.Action {
	case "run", "end", "enable", "disable", "delete":
	default:
		return errors.New("unknown action")
	}
	if t.Name == "" || len(t.Name) > 260 || len(t.Path) > 500 || !strings.HasPrefix(t.Path, `\`) || !strings.HasSuffix(t.Path, `\`) ||
		strings.ContainsAny(t.Name+t.Path, "\x00\r\n'\"`$") {
		return errors.New("bad task name")
	}
	return nil
}
