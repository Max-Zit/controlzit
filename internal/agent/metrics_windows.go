//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"os/exec"
	"sort"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/max-zit/controlzit/internal/proto"
)

var (
	procGetSystemTimes       = kernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func ft(f windows.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }

// metricsState keeps what the samples need between heartbeats.
type metricsState struct {
	mu                 sync.Mutex
	idle, kernel, user uint64
	lastServices       time.Time
	lastSecurity       time.Time
}

var metricsPrev metricsState

func cpuPercent() float64 {
	var idle, kernel, user windows.Filetime
	if r, _, _ := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user))); r == 0 { // #nosec G103 -- Win32 out-parameters
		return 0
	}
	i, k, u := ft(idle), ft(kernel), ft(user)
	m := &metricsPrev
	di, dk, du := i-m.idle, k-m.kernel, u-m.user
	first := m.kernel == 0
	m.idle, m.kernel, m.user = i, k, u
	total := dk + du // kernel time includes idle time
	if first || total == 0 {
		return 0
	}
	busy := float64(total-di) / float64(total) * 100
	return max(0, min(100, busy))
}

// CollectMetrics samples the machine for a heartbeat.
func CollectMetrics(ctx context.Context) *proto.Metrics {
	m := &metricsPrev
	m.mu.Lock()
	defer m.mu.Unlock()
	out := &proto.Metrics{CPU: cpuPercent()}
	ms := memoryStatusEx{}
	ms.Length = uint32(unsafe.Sizeof(ms))
	if r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms))); r != 0 { // #nosec G103 -- Win32 struct
		out.MemTotal, out.MemUsed = ms.TotalPhys, ms.TotalPhys-ms.AvailPhys
	}
	if ds, err := drives(); err == nil {
		for _, d := range ds {
			if d.Type == "fixed" && d.Size > 0 {
				out.Disks = append(out.Disks, proto.Disk{Drive: d.Path[:2], Label: d.Label, Size: d.Size, Free: d.Free})
			}
		}
	}
	now := time.Now()
	if now.Sub(m.lastServices) >= 5*time.Minute {
		m.lastServices = now
		out.StoppedAuto = stoppedAutoServices()
		if out.StoppedAuto == nil {
			out.StoppedAuto = []string{}
		}
	}
	if now.Sub(m.lastSecurity) >= 15*time.Minute {
		m.lastSecurity = now
		out.Security = securityState(ctx)
	}
	return out
}

// stoppedAutoServices lists services with start type Automatic that are
// not running (the server alerts on the ones in its watch list).
func stoppedAutoServices() []string {
	sm, err := mgr.Connect()
	if err != nil {
		return nil
	}
	defer sm.Disconnect()
	names, err := sm.ListServices()
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range names {
		s, err := sm.OpenService(n)
		if err != nil {
			continue
		}
		cfg, err1 := s.Config()
		st, err2 := s.Query()
		_ = s.Close()
		if err1 != nil || err2 != nil {
			continue
		}
		if cfg.StartType == mgr.StartAutomatic && st.State != 4 /* SERVICE_RUNNING */ {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

const securityScript = `$ErrorActionPreference='SilentlyContinue'
$r=[ordered]@{defender_present=$false;defender_av=$false;defender_rt=$false;firewall=@();pending_reboot=$false}
if (Get-Command Get-MpComputerStatus) { $mp=Get-MpComputerStatus; if ($mp) { $r.defender_present=$true; $r.defender_av=[bool]$mp.AntivirusEnabled; $r.defender_rt=[bool]$mp.RealTimeProtectionEnabled } }
$r.firewall=@(Get-NetFirewallProfile | ForEach-Object { [ordered]@{profile=[string]$_.Name; enabled=[bool]("$($_.Enabled)" -eq 'True')} })
$p=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
$r.pending_reboot=[bool]$p
$r | ConvertTo-Json -Depth 4 -Compress`

func securityState(ctx context.Context) *proto.SecurityState {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodeCommand(securityScript)) // #nosec G204 -- fixed system binary and embedded script
	cmd.SysProcAttr = hiddenProc
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var s proto.SecurityState
	if json.Unmarshal(out, &s) != nil {
		return nil
	}
	s.CheckedAt = time.Now().UTC()
	return &s
}
