//go:build windows

package agent

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func installedService() bool { return isSystem() }

// startUninstall runs msiexec /x for the installed RMMZit Agent product
// on its own: it stops and removes this service.
func startUninstall() error {
	code, err := productCode()
	if err != nil {
		return err
	}
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "msiexec.exe")
	logPath := filepath.Join(helperDir, "uninstall.log")
	cmd := exec.Command(exe, "/x", code, "/qn", "/norestart", "/l*v", logPath) // #nosec G204 G702 -- msiexec with the {GUID} product code from the uninstall list
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// productCode finds the installed product in the uninstall list.
func productCode() (string, error) {
	const list = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, list, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return "", err
	}
	for _, n := range names {
		if len(n) != 38 || n[0] != '{' {
			continue // MSI products are named by their {GUID}
		}
		sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		name, _, _ := sk.GetStringValue("DisplayName")
		_ = sk.Close()
		if name == "RMMZit Agent" || name == "ControlZit Agent" { // ControlZit: the name before RMMZit
			return n, nil
		}
	}
	return "", errors.New("the RMMZit Agent product is not in the uninstall list")
}
