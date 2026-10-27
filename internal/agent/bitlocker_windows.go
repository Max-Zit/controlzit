//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
)

// BitLocker through the BitLocker PowerShell module as SYSTEM: the volumes
// with their recovery passwords, and switching it on for the system drive.
// The console first calls prepare (which adds a recovery password and
// returns it), stores the key, and only then calls enable.

func init() { register(proto.KindBitLocker, runBitLocker) }

const bitlockerCommon = patchCommonOut + `
if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) { throw 'BitLocker is not available on this Windows edition' }
function Report($started) {
  $tpm = $null; try { $tpm = Get-Tpm } catch {}
  $vols = @(Get-BitLockerVolume | ForEach-Object {
    [pscustomobject]@{
      mount = [string]$_.MountPoint; type = [string]$_.VolumeType; protection = [string]$_.ProtectionStatus
      status = [string]$_.VolumeStatus; percent = [double]$_.EncryptionPercentage
      keys = @($_.KeyProtector | Where-Object { [string]$_.KeyProtectorType -eq 'RecoveryPassword' } | ForEach-Object {
        [pscustomobject]@{ id = [string]$_.KeyProtectorId; password = [string]$_.RecoveryPassword } })
    } })
  Write-Result ([pscustomobject]@{ tpm_present = [bool]($tpm -and $tpm.TpmPresent); tpm_ready = [bool]($tpm -and $tpm.TpmReady); volumes = $vols; started = [bool]$started })
}
$sd = $env:SystemDrive
`

const bitlockerKeysScript = bitlockerCommon + `Report $false
`

const bitlockerPrepareScript = bitlockerCommon + `$tpm = Get-Tpm
if (-not $tpm.TpmPresent) { throw 'this computer has no TPM' }
if (-not $tpm.TpmReady) { throw 'the TPM is not ready (initialize it in the firmware or with Initialize-Tpm)' }
$v = Get-BitLockerVolume -MountPoint $sd
if (-not ($v.KeyProtector | Where-Object { [string]$_.KeyProtectorType -eq 'RecoveryPassword' })) {
  Add-BitLockerKeyProtector -MountPoint $sd -RecoveryPasswordProtector -WarningAction SilentlyContinue | Out-Null
}
Report $false
`

const bitlockerEnableScript = bitlockerCommon + `$v = Get-BitLockerVolume -MountPoint $sd
if (-not ($v.KeyProtector | Where-Object { [string]$_.KeyProtectorType -eq 'RecoveryPassword' })) { throw 'the system drive has no recovery key; prepare first' }
$started = $false
if ([string]$v.VolumeStatus -eq 'FullyDecrypted') {
  Enable-BitLocker -MountPoint $sd -TpmProtector -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest -WarningAction SilentlyContinue | Out-Null
  $started = $true
} elseif ([string]$v.ProtectionStatus -eq 'Off') {
  # Encrypted but not protected (Windows device encryption waiting for
  # activation, or suspended): add the TPM protector and resume.
  if (-not ($v.KeyProtector | Where-Object { [string]$_.KeyProtectorType -eq 'Tpm' })) {
    Add-BitLockerKeyProtector -MountPoint $sd -TpmProtector -WarningAction SilentlyContinue | Out-Null
  }
  Resume-BitLocker -MountPoint $sd | Out-Null
  $started = $true
}
Report $started
`

func runBitLocker(ctx context.Context, raw json.RawMessage) (any, error) {
	var a proto.BitLockerArgs
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	script := map[string]string{proto.BitLockerKeys: bitlockerKeysScript, proto.BitLockerPrepare: bitlockerPrepareScript, proto.BitLockerEnable: bitlockerEnableScript}[a.Action]
	if script == "" {
		return nil, errors.New("unknown action")
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	return BitLocker(cctx, a.Action, script)
}

// BitLocker runs a BitLocker script (tests replace it).
var BitLocker = func(ctx context.Context, action, script string) (*proto.BitLockerReport, error) {
	var r proto.BitLockerReport
	if err := runPSJSON(ctx, script, &r, "BitLocker"); err != nil {
		return nil, err
	}
	return &r, nil
}
