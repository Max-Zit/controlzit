//go:build windows

package agent

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"unicode/utf16"

	"github.com/max-zit/controlzit/internal/proto"
)

//go:embed inventory.ps1
var inventoryScript string

// powershell is the Windows PowerShell of the system (not one on PATH).
func powershell() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}

// encodeCommand is the -EncodedCommand form (UTF-16LE, base64): no quoting.
func encodeCommand(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// CollectInventory runs the inventory script (CIM, registry, Defender,
// firewall cmdlets — all built into Windows).
func CollectInventory(ctx context.Context) *proto.Inventory {
	inv := &proto.Inventory{CollectedAt: time.Now().UTC()}
	cmd := exec.CommandContext(ctx, powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodeCommand(inventoryScript)) // #nosec G204 -- fixed system binary and embedded script
	cmd.SysProcAttr = hiddenProc
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		inv.Errors = append(inv.Errors, "powershell: "+err.Error()+": "+trim(errb.String(), 500))
		inv.Hostname, _ = os.Hostname()
		return inv
	}
	if err := json.Unmarshal(bytes.TrimPrefix(out.Bytes(), []byte("\xef\xbb\xbf")), inv); err != nil {
		inv.Errors = append(inv.Errors, "inventory output: "+err.Error()+": "+trim(out.String(), 300))
	}
	if inv.Hostname == "" {
		inv.Hostname, _ = os.Hostname()
	}
	return inv
}
