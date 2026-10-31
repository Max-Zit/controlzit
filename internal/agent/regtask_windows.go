//go:build windows

package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/max-zit/rmmzit/internal/proto"
)

func init() {
	register(proto.KindRegList, regList)
	register(proto.KindRegSet, regSet)
	register(proto.KindRegDelete, regDelete)
	register(proto.KindRegNewKey, regNewKey)
	register(proto.KindTaskList, taskList)
	register(proto.KindTaskCtl, taskControl)
}

// ---- registry

const (
	regMaxItems  = 3000 // subkeys or values listed at most
	regMaxBinary = 512  // bytes of a binary value shown
	regMaxString = 64 << 10
)

var regRootKeys = map[string]registry.Key{"HKLM": registry.LOCAL_MACHINE, "HKU": registry.USERS, "HKCR": registry.CLASSES_ROOT, "HKCC": registry.CURRENT_CONFIG}

// regOpen opens a cleaned path with access (64-bit view).
func regOpen(path string, access uint32) (registry.Key, error) {
	root, sub, _ := strings.Cut(path, `\`)
	if sub == "" {
		return regRootKeys[root], nil
	}
	k, err := registry.OpenKey(regRootKeys[root], sub, access|registry.WOW64_64KEY)
	if err != nil {
		return 0, regErr(err)
	}
	return k, nil
}

func regErr(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, registry.ErrNotExist):
		return errors.New("the key or value does not exist")
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return errors.New("access denied (even SYSTEM may not open this key)")
	}
	return err
}

func regList(_ context.Context, raw json.RawMessage) (any, error) {
	var a proto.RegPath
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	path, err := proto.CleanRegPath(a.Path)
	if err != nil {
		return nil, err
	}
	k, err := regOpen(path, registry.READ)
	if err != nil {
		return nil, err
	}
	if strings.Contains(path, `\`) {
		defer k.Close()
	}
	out := &proto.RegKey{Path: path, Subkeys: []string{}, Values: []proto.RegValue{}}
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil && len(subs) == 0 {
		return nil, regErr(err)
	}
	if len(subs) > regMaxItems {
		subs, out.More = subs[:regMaxItems], true
	}
	sort.Slice(subs, func(i, j int) bool { return strings.ToLower(subs[i]) < strings.ToLower(subs[j]) })
	out.Subkeys = subs
	names, _ := k.ReadValueNames(-1)
	if len(names) > regMaxItems {
		names, out.More = names[:regMaxItems], true
	}
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	for _, n := range names {
		if v, err := regRead(k, n); err == nil {
			out.Values = append(out.Values, v)
		}
	}
	return out, nil
}

var regTypeNames = map[uint32]string{registry.SZ: "REG_SZ", registry.EXPAND_SZ: "REG_EXPAND_SZ", registry.BINARY: "REG_BINARY",
	registry.DWORD: "REG_DWORD", registry.DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN", registry.LINK: "REG_LINK", registry.MULTI_SZ: "REG_MULTI_SZ",
	registry.RESOURCE_LIST: "REG_RESOURCE_LIST", registry.FULL_RESOURCE_DESCRIPTOR: "REG_FULL_RESOURCE_DESCRIPTOR",
	registry.RESOURCE_REQUIREMENTS_LIST: "REG_RESOURCE_REQUIREMENTS_LIST", registry.QWORD: "REG_QWORD", registry.NONE: "REG_NONE"}

// regRead reads a value as text.
func regRead(k registry.Key, name string) (proto.RegValue, error) {
	_, typ, err := k.GetValue(name, nil)
	if err != nil {
		return proto.RegValue{}, err
	}
	v := proto.RegValue{Name: name, Type: regTypeNames[typ]}
	if v.Type == "" {
		v.Type = "REG_" + strconv.FormatUint(uint64(typ), 10)
	}
	switch typ {
	case registry.SZ, registry.EXPAND_SZ:
		v.Data, _, err = k.GetStringValue(name)
	case registry.DWORD, registry.QWORD:
		var n uint64
		n, _, err = k.GetIntegerValue(name)
		v.Data = strconv.FormatUint(n, 10)
	case registry.MULTI_SZ:
		var list []string
		list, _, err = k.GetStringsValue(name)
		v.Data = strings.Join(list, "\n")
	default:
		buf := make([]byte, 64<<10)
		var n int
		n, _, err = k.GetValue(name, buf)
		if err == nil {
			b := buf[:min(n, len(buf))]
			more := ""
			if len(b) > regMaxBinary {
				b, more = b[:regMaxBinary], " …"
			}
			v.Data = hex.EncodeToString(b) + more
		}
	}
	if len(v.Data) > regMaxString {
		v.Data = v.Data[:regMaxString] + " …"
	}
	return v, err
}

// RegSetResult tells what the value was before (for the audit log).
type RegSetResult struct {
	Old *proto.RegValue `json:"old,omitempty"`
}

func regSet(_ context.Context, raw json.RawMessage) (any, error) {
	var a proto.RegSet
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	path, err := proto.CleanRegPath(a.Path)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(path, `\`) {
		return nil, errors.New("values cannot be written to a root key")
	}
	if len(a.Name) > 16383 || len(a.Data) > regMaxString || strings.ContainsRune(a.Name, 0) {
		return nil, errors.New("value name or data too long")
	}
	k, err := regOpen(path, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	res := RegSetResult{}
	if old, err := regRead(k, a.Name); err == nil {
		res.Old = &old
	}
	switch a.Type {
	case "REG_SZ":
		err = k.SetStringValue(a.Name, a.Data)
	case "REG_EXPAND_SZ":
		err = k.SetExpandStringValue(a.Name, a.Data)
	case "REG_DWORD":
		var n uint64
		if n, err = parseRegNumber(a.Data, 32); err == nil {
			err = k.SetDWordValue(a.Name, uint32(n)) // #nosec G115 -- parsed as 32 bits
		}
	case "REG_QWORD":
		var n uint64
		if n, err = parseRegNumber(a.Data, 64); err == nil {
			err = k.SetQWordValue(a.Name, n)
		}
	case "REG_MULTI_SZ":
		lines := strings.Split(strings.ReplaceAll(a.Data, "\r\n", "\n"), "\n")
		for len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		err = k.SetStringsValue(a.Name, lines)
	default:
		return nil, errors.New("this value type cannot be written here")
	}
	if err != nil {
		return nil, regErr(err)
	}
	return res, nil
}

// parseRegNumber reads a decimal or 0x-hex number of bits size.
func parseRegNumber(s string, bits int) (uint64, error) {
	s = strings.TrimSpace(s)
	base := 10
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s, base = s[2:], 16
	}
	n, err := strconv.ParseUint(s, base, bits)
	if err != nil {
		return 0, fmt.Errorf("not a %d-bit number", bits)
	}
	return n, nil
}

func regDelete(_ context.Context, raw json.RawMessage) (any, error) {
	var a proto.RegDelete
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	path, err := proto.CleanRegPath(a.Path)
	if err != nil {
		return nil, err
	}
	if a.Key {
		if proto.ProtectedRegKey(path) {
			return nil, errors.New("this key is protected and cannot be deleted from the console")
		}
		parent, name := path[:strings.LastIndex(path, `\`)], path[strings.LastIndex(path, `\`)+1:]
		pk, err := regOpen(parent, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if err != nil {
			return nil, err
		}
		defer pk.Close()
		return nil, regDeleteTree(pk, name, 0)
	}
	k, err := regOpen(path, registry.SET_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	return nil, regErr(k.DeleteValue(a.Name))
}

// regDeleteTree deletes parent\name with its subkeys.
func regDeleteTree(parent registry.Key, name string, depth int) error {
	if depth > 64 {
		return errors.New("the key tree is too deep")
	}
	k, err := registry.OpenKey(parent, name, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|registry.WOW64_64KEY|windows.DELETE)
	if err != nil {
		return regErr(err)
	}
	subs, _ := k.ReadSubKeyNames(-1)
	for _, s := range subs {
		if err := regDeleteTree(k, s, depth+1); err != nil {
			_ = k.Close()
			return err
		}
	}
	_ = k.Close()
	return regErr(registry.DeleteKey(parent, name))
}

func regNewKey(_ context.Context, raw json.RawMessage) (any, error) {
	var a proto.RegNewKey
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	path, err := proto.CleanRegPath(a.Path + `\` + a.Name)
	if err != nil || strings.Contains(a.Name, `\`) || strings.TrimSpace(a.Name) == "" {
		return nil, errors.New("bad key name")
	}
	root, sub, _ := strings.Cut(path, `\`)
	k, _, err := registry.CreateKey(regRootKeys[root], sub, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil, regErr(err)
	}
	_ = k.Close()
	return nil, nil
}

// ---- scheduled tasks

const taskListScript = `$ErrorActionPreference = 'SilentlyContinue'
$w = New-Object IO.StreamWriter([Console]::OpenStandardOutput(), (New-Object Text.UTF8Encoding $false))
$all = @ALL@
function T($d) { if ($d -and $d.Year -gt 2000) { $d.ToUniversalTime().ToString('o') } else { '' } }
$out = @(Get-ScheduledTask | Where-Object { $all -or $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
  $i = $_ | Get-ScheduledTaskInfo
  $a = $_.Actions | Select-Object -First 1
  $cmd = ''
  if ($a.Execute) { $cmd = ([string]$a.Execute + ' ' + [string]$a.Arguments).Trim() } elseif ($a) { $cmd = [string]$a.CimClass.CimClassName }
  [pscustomobject]@{ path = [string]$_.TaskPath; name = [string]$_.TaskName; state = [string]$_.State; last_run = (T $i.LastRunTime);
    last_result = [int64]$i.LastTaskResult; next_run = (T $i.NextRunTime); author = [string]$_.Author; run_as = [string]$_.Principal.UserId; action = $cmd }
})
$w.Write((ConvertTo-Json -InputObject $out -Depth 3 -Compress)); $w.Flush()
`

func taskList(ctx context.Context, raw json.RawMessage) (any, error) {
	var a proto.TaskList
	_ = args(raw, &a)
	all := "$false"
	if a.All {
		all = "$true"
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	var list []proto.SchedTask
	if err := runPSJSON(ctx, strings.Replace(taskListScript, "@ALL@", all, 1), &list, "Task Scheduler"); err != nil {
		return nil, err
	}
	sort.Slice(list, func(i, j int) bool {
		return strings.ToLower(list[i].Path+list[i].Name) < strings.ToLower(list[j].Path+list[j].Name)
	})
	return list, nil
}

func taskControl(ctx context.Context, raw json.RawMessage) (any, error) {
	var a proto.TaskControl
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	if err := proto.ValidTaskControl(a); err != nil {
		return nil, err
	}
	cmdlet := map[string]string{"run": "Start-ScheduledTask", "end": "Stop-ScheduledTask", "enable": "Enable-ScheduledTask",
		"disable": "Disable-ScheduledTask", "delete": "Unregister-ScheduledTask -Confirm:$false"}[a.Action]
	// Names are checked: no quotes, so they are safe in single quotes.
	script := "$ErrorActionPreference = 'Stop'\n" + cmdlet + " -TaskPath '" + a.Path + "' -TaskName '" + a.Name + "' | Out-Null\n" +
		"[Console]::Out.Write('{\"ok\":true}')\n"
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	var ok struct{ OK bool }
	return nil, runPSJSON(ctx, script, &ok, "Task Scheduler")
}
