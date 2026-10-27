package web

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/store"
)

const settingMonitoring = "monitoring"

// MonitoringSettings are the alert rules (one policy for all devices).
type MonitoringSettings struct {
	CPUPercent     int      `json:"cpu_percent"`
	CPUMinutes     int      `json:"cpu_minutes"`
	MemPercent     int      `json:"mem_percent"`
	MemMinutes     int      `json:"mem_minutes"`
	DiskPercent    int      `json:"disk_percent"`
	DiskMinFreeGB  int      `json:"disk_min_free_gb"`
	OfflineMinutes int      `json:"offline_minutes"`
	RebootDays     int      `json:"reboot_days"`
	DefenderOff    bool     `json:"defender_off"`
	FirewallOff    bool     `json:"firewall_off"`
	WatchServices  []string `json:"watch_services"`
	DiskHealthOff  bool     `json:"disk_health_off,omitempty"`
	VulnAlerts     bool     `json:"vuln_alerts,omitempty"`
	EmailOnOpen    bool     `json:"email_on_open"`
	EmailOnResolve bool     `json:"email_on_resolve"`
	Recipients     []string `json:"recipients"`
}

func defaultMonitoring() MonitoringSettings {
	return MonitoringSettings{CPUPercent: 90, CPUMinutes: 15, MemPercent: 90, MemMinutes: 15, DiskPercent: 90, DiskMinFreeGB: 5,
		OfflineMinutes: 15, RebootDays: 7, DefenderOff: true, FirewallOff: true}
}

// Validate checks the ranges.
func (m *MonitoringSettings) Validate() error {
	switch {
	case m.CPUPercent < 50 || m.CPUPercent > 100 || m.MemPercent < 50 || m.MemPercent > 100:
		return errors.New("CPU and memory thresholds must be 50–100 %")
	case m.CPUMinutes < 2 || m.CPUMinutes > 240 || m.MemMinutes < 2 || m.MemMinutes > 240:
		return errors.New("the load period must be 2–240 minutes")
	case m.DiskPercent < 50 || m.DiskPercent > 100 || m.DiskMinFreeGB < 0 || m.DiskMinFreeGB > 10000:
		return errors.New("disk thresholds are out of range")
	case m.OfflineMinutes < 3 || m.OfflineMinutes > 10080:
		return errors.New("the offline time must be 3–10080 minutes")
	case m.RebootDays < 0 || m.RebootDays > 365:
		return errors.New("the restart days must be 0–365")
	case len(m.WatchServices) > 100 || len(m.Recipients) > 50:
		return errors.New("too many services or recipients")
	}
	for _, r := range m.Recipients {
		if _, err := mail.ParseAddress(r); err != nil {
			return fmt.Errorf("%q is not an email address", r)
		}
	}
	return nil
}

// Monitoring loads the rules.
func (s *Server) Monitoring(ctx context.Context) MonitoringSettings {
	m := defaultMonitoring()
	if err := s.store.GetSetting(ctx, settingMonitoring, &m); err != nil || m.Validate() != nil {
		return defaultMonitoring()
	}
	return m
}

// Alert kinds.
const (
	AlertOffline  = "offline"
	AlertCPU      = "cpu"
	AlertMemory   = "memory"
	AlertDisk     = "disk"
	AlertReboot   = "reboot"
	AlertDefender = "defender"
	AlertFirewall = "firewall"
	AlertService  = "service"
)

// alertTitles name the kinds (translated in the console).
var alertTitles = map[string]string{
	AlertOffline: "Device offline", AlertCPU: "High CPU load", AlertMemory: "High memory use", AlertDisk: "Low disk space",
	AlertReboot: "Restart pending", AlertDefender: "Microsoft Defender off", AlertFirewall: "Firewall off", AlertService: "Service stopped",
}

func gb(b uint64) string { return fmt.Sprintf("%.1f GB", float64(b)/(1<<30)) }

// evaluate applies the rules to the devices. Offline devices keep their
// other open alerts (the data is old, not good news); keep lists them.
func evaluate(m MonitoringSettings, states []store.MonitorState, now time.Time) (conds []store.Condition, keep map[int64]bool) {
	keep = map[int64]bool{}
	watch := map[string]bool{}
	for _, w := range m.WatchServices {
		watch[strings.ToLower(strings.TrimSpace(w))] = true
	}
	for _, d := range states {
		add := func(kind, key, sev, msg string) {
			conds = append(conds, store.Condition{DeviceID: d.ID, Kind: kind, Key: key, Severity: sev, Message: msg})
		}
		if d.LastSeen == nil {
			continue // never connected
		}
		if !d.Connected || now.Sub(*d.LastSeen) > 3*time.Minute {
			if now.Sub(*d.LastSeen) >= time.Duration(m.OfflineMinutes)*time.Minute {
				add(AlertOffline, "", "critical", "last seen "+d.LastSeen.UTC().Format("2006-01-02 15:04 UTC"))
			}
			keep[d.ID] = true
			continue
		}
		// Sustained load needs most of the window covered by samples.
		if d.Samples >= m.CPUMinutes*2/3 && d.AvgCPU >= float64(m.CPUPercent) {
			add(AlertCPU, "", "warning", fmt.Sprintf("%.0f %% average over %d min", d.AvgCPU, m.CPUMinutes))
		}
		if d.Samples >= m.MemMinutes*2/3 && d.AvgMem >= float64(m.MemPercent) {
			add(AlertMemory, "", "warning", fmt.Sprintf("%.0f %% average over %d min", d.AvgMem, m.MemMinutes))
		}
		if d.Metrics != nil {
			for _, dk := range d.Metrics.Disks {
				if dk.Size == 0 {
					continue
				}
				used := float64(dk.Size-dk.Free) / float64(dk.Size) * 100
				// The GB limit is for larger disks; small ones go by the percentage.
				minFree := uint64(m.DiskMinFreeGB) << 30 // #nosec G115 -- bounded by Validate
				lowFree := minFree > 0 && dk.Size > 2*minFree && dk.Free < minFree
				if used >= float64(m.DiskPercent) || lowFree {
					sev := "warning"
					if dk.Free < 1<<30 || used >= 98 {
						sev = "critical"
					}
					add(AlertDisk, dk.Drive, sev, fmt.Sprintf("%s free of %s (%.0f %% used)", gb(dk.Free), gb(dk.Size), used))
				}
			}
		}
		if sec := d.Security; sec != nil {
			if sec.PendingReboot && d.BootTime != nil && now.Sub(*d.BootTime) >= time.Duration(m.RebootDays)*24*time.Hour {
				add(AlertReboot, "", "warning", fmt.Sprintf("up for %d days", int(now.Sub(*d.BootTime).Hours()/24)))
			}
			if m.DefenderOff && sec.DefenderPresent && (!sec.DefenderAV || !sec.DefenderRealTime) {
				add(AlertDefender, "", "critical", "antivirus or real-time protection is off")
			}
			if m.FirewallOff {
				for _, f := range sec.Firewall {
					if !f.Enabled {
						add(AlertFirewall, f.Profile, "warning", f.Profile+" profile is off")
					}
				}
			}
		}
		for _, svc := range d.StoppedAuto {
			if watch[strings.ToLower(svc)] {
				add(AlertService, svc, "critical", svc+" is not running")
			}
		}
	}
	return conds, keep
}
