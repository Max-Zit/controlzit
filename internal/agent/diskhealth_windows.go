//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
)

// Disk health on Windows: the physical disks with their storage reliability
// counters (SMART, read by Windows) and the Storage Spaces virtual disks.

func init() { register(proto.KindDiskHealth, diskHealth) }

const diskHealthScript = `$ErrorActionPreference = 'Stop'
$out = [ordered]@{ disks = @(); arrays = @(); errors = @() }
try {
  foreach ($d in Get-PhysicalDisk) {
    $r = $null
    try { $r = $d | Get-StorageReliabilityCounter } catch {}
    $errs = 0; $wear = -1; $temp = 0; $hours = 0
    if ($r) {
      $errs = [int]$r.ReadErrorsUncorrected + [int]$r.WriteErrorsUncorrected
      if ($null -ne $r.Wear) { $wear = [int]$r.Wear }
      if ($r.Temperature) { $temp = [int]$r.Temperature }
      if ($r.PowerOnHours) { $hours = [int]$r.PowerOnHours }
    }
    $out.disks += [ordered]@{ model = [string]$d.FriendlyName; serial = ([string]$d.SerialNumber).Trim(); media = [string]$d.MediaType
      bus = [string]$d.BusType; size_gb = [int]([int64]$d.Size / 1GB); health = [string]$d.HealthStatus
      status = (@($d.OperationalStatus) -join ', '); temp_c = $temp; wear = $wear; power_on_hours = $hours; errors = $errs }
  }
} catch { $out.errors += 'physical disks: ' + $_.Exception.Message }
try {
  foreach ($v in Get-VirtualDisk) {
    $out.arrays += [ordered]@{ name = [string]$v.FriendlyName; level = [string]$v.ResiliencySettingName
      health = [string]$v.HealthStatus; state = (@($v.OperationalStatus) -join ', ') }
  }
} catch {}
$out | ConvertTo-Json -Depth 4 -Compress`

func diskHealth(ctx context.Context, _ json.RawMessage) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var h proto.DiskHealth
	if err := runPSJSON(ctx, diskHealthScript, &h, "disk health"); err != nil {
		return nil, err
	}
	for i := range h.Disks {
		d := &h.Disks[i]
		d.Health = windowsHealth(d.Health)
		if d.Health == proto.HealthOK && d.Errors > 0 {
			d.Health = proto.HealthWarning
		}
		if d.Media == "Unspecified" {
			d.Media = ""
		}
	}
	for i := range h.Arrays {
		h.Arrays[i].Health = windowsHealth(h.Arrays[i].Health)
	}
	return h, nil
}

// windowsHealth maps HealthStatus (Healthy, Warning, Unhealthy, Unknown).
func windowsHealth(s string) string {
	switch strings.ToLower(s) {
	case "healthy", "0":
		return proto.HealthOK
	case "warning", "1":
		return proto.HealthWarning
	case "unhealthy", "2":
		return proto.HealthFailing
	}
	return proto.HealthUnknown
}
