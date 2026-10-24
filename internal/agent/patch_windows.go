//go:build windows

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
)

// The Windows Update Agent API (COM) from PowerShell, which every Windows has.

const patchCommon = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$stdout = New-Object IO.StreamWriter([Console]::OpenStandardOutput(), (New-Object Text.UTF8Encoding $false))
function Write-Result($o) { $stdout.Write(($o | ConvertTo-Json -Depth 4 -Compress)); $stdout.Flush() }
$session = New-Object -ComObject Microsoft.Update.Session
$session.ClientApplicationID = 'ControlZit'
$searcher = $session.CreateUpdateSearcher()
`

const patchScanScript = patchCommon + `$found = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
$updates = @(foreach ($u in $found.Updates) {
  $pub = $null; try { $pub = $u.LastDeploymentChangeTime.ToUniversalTime().ToString('o') } catch {}
  [pscustomobject]@{
    id = [string]$u.Identity.UpdateID; title = [string]$u.Title
    kb = (@($u.KBArticleIDs) | ForEach-Object { 'KB' + $_ }) -join ', '
    severity = [string]$u.MsrcSeverity
    categories = @($u.Categories | ForEach-Object { [string]$_.Name })
    size = [int64]$u.MaxDownloadSize
    reboot = ($u.InstallationBehavior.RebootBehavior -ne 0)
    published = $pub; downloaded = [bool]$u.IsDownloaded
  }
})
$history = @()
$n = $searcher.GetTotalHistoryCount()
if ($n -gt 0) {
  $history = @(foreach ($h in $searcher.QueryHistory(0, [Math]::Min($n, 40))) {
    if ($h.Operation -ne 1 -or -not $h.Title) { continue }
    [pscustomobject]@{ title = [string]$h.Title; date = $h.Date.ToUniversalTime().ToString('o'); result = [int]$h.ResultCode }
  })
}
$reboot = (New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired
Write-Result ([pscustomobject]@{ updates = $updates; history = $history; reboot = [bool]$reboot })
`

const patchInstallScript = patchCommon + `$found = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
$todo = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $found.Updates) {
  if ($ids -contains [string]$u.Identity.UpdateID) {
    if (-not $u.EulaAccepted) { $u.AcceptEula() }
    [void]$todo.Add($u)
  }
}
if ($todo.Count -eq 0) { Write-Result ([pscustomobject]@{ result = 2; reboot = $false; results = @() }); exit 0 }
$dl = $session.CreateUpdateDownloader(); $dl.Updates = $todo; [void]$dl.Download()
$inst = $session.CreateUpdateInstaller(); $inst.Updates = $todo
$res = $inst.Install()
$results = @(for ($i = 0; $i -lt $todo.Count; $i++) {
  $r = $res.GetUpdateResult($i)
  [pscustomobject]@{ id = [string]$todo.Item($i).Identity.UpdateID; title = [string]$todo.Item($i).Title; result = [int]$r.ResultCode; hresult = [int64]$r.HResult }
})
Write-Result ([pscustomobject]@{ result = [int]$res.ResultCode; reboot = [bool]$res.RebootRequired; results = $results })
`

// runPatchScript runs a script and decodes its JSON output into v.
func runPatchScript(ctx context.Context, script string, v any) error {
	cmd := exec.CommandContext(ctx, powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodeCommand(script)) // #nosec G204 -- embedded script, validated IDs
	cmd.SysProcAttr = hiddenProc
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return errors.New("the update service did not answer in time")
		}
		return fmt.Errorf("update service: %s", psError(errb.String(), err))
	}
	b := bytes.TrimSpace(bytes.TrimPrefix(out.Bytes(), []byte("\xef\xbb\xbf")))
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("update service output: %v: %s", err, trim(string(b), 200))
	}
	return nil
}

// psError picks the message of a PowerShell error from its CLIXML stderr.
func psError(stderr string, err error) string {
	if i := strings.Index(stderr, `<S S="Error">`); i >= 0 {
		msg := stderr[i+len(`<S S="Error">`):]
		if j := strings.Index(msg, "</S>"); j >= 0 {
			msg = msg[:j]
		}
		return strings.TrimSpace(strings.ReplaceAll(msg, "_x000D__x000A_", " "))
	}
	return err.Error()
}

func patchScan(ctx context.Context) (*PatchScanResult, error) {
	var r PatchScanResult
	if err := runPatchScript(ctx, patchScanScript, &r); err != nil {
		return nil, err
	}
	if len(r.Updates) > 1000 {
		r.Updates = r.Updates[:1000]
	}
	return &r, nil
}

func patchInstall(ctx context.Context, ids []string) (*PatchInstallResult, error) {
	quoted := make([]string, 0, len(ids))
	for _, id := range ids {
		if !proto.ValidGUID(id) {
			return nil, errors.New("bad update ID")
		}
		quoted = append(quoted, "'"+strings.ToLower(id)+"'")
	}
	script := "$ids = @(" + strings.Join(quoted, ",") + ")\n" + patchInstallScript
	var r PatchInstallResult
	if err := runPatchScript(ctx, script, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// scheduleRestart restarts Windows after d with a notice to signed-in users.
func scheduleRestart(d time.Duration, msg string) error {
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "shutdown.exe")
	out, err := exec.Command(exe, "/r", "/t", strconv.Itoa(int(d.Seconds())), "/d", "p:2:17", "/c", msg).CombinedOutput() // #nosec G702 G204 -- fixed system binary and text
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
