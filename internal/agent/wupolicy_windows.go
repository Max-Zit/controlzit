//go:build windows

package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// RMMZit installs Windows updates on its own schedule, so the agent
// switches off the automatic installation and restarts of Windows Update
// (by policy, as Group Policy would). The values it finds first are saved
// and put back when the agent is removed.

const (
	wuPolicyKey    = `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`
	wuPolicyBackup = "wu-policy-backup.json"
)

// wuPolicy are the values the agent sets.
var wuPolicy = map[string]uint32{
	"NoAutoUpdate":                  1, // no automatic download and installation
	"NoAutoRebootWithLoggedOnUsers": 1, // never restart while someone is signed in
}

type savedValue struct {
	Present bool   `json:"present"`
	Value   uint32 `json:"value"`
}

// ApplyWUPolicy sets the policy (once the original values are saved); only
// the agent running as the service does.
func ApplyWUPolicy(dir string) error {
	if !isSystem() {
		return nil // only the installed service (tests, a technician run)
	}
	backup := filepath.Join(dir, wuPolicyBackup)
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, wuPolicyKey, registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	if _, err := os.Stat(backup); errors.Is(err, os.ErrNotExist) {
		saved := map[string]savedValue{}
		for name := range wuPolicy {
			v, _, err := k.GetIntegerValue(name)
			saved[name] = savedValue{Present: err == nil, Value: uint32(v)} // #nosec G115 -- DWORD values
		}
		b, _ := json.Marshal(saved)
		if err := os.WriteFile(backup, b, 0o600); err != nil {
			return err
		}
	}
	for name, v := range wuPolicy {
		if err := k.SetDWordValue(name, v); err != nil {
			return err
		}
	}
	return nil
}

// RestoreWUPolicy puts back the values found before the agent changed them.
func RestoreWUPolicy(dir string) error {
	backup := filepath.Join(dir, wuPolicyBackup)
	b, err := os.ReadFile(backup) // #nosec G304 -- our own data directory
	if errors.Is(err, os.ErrNotExist) {
		return nil // never applied
	}
	if err != nil {
		return err
	}
	var saved map[string]savedValue
	if err := json.Unmarshal(b, &saved); err != nil {
		return err
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, wuPolicyKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err == nil {
		for name := range wuPolicy {
			if s, ok := saved[name]; ok && s.Present {
				_ = k.SetDWordValue(name, s.Value)
			} else {
				_ = k.DeleteValue(name)
			}
		}
		_ = k.Close()
	}
	return os.Remove(backup)
}
