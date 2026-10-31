//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
)

// Disk health on Linux: SMART through smartctl (smartmontools, when it is
// installed) and the md software RAID arrays of /proc/mdstat.

func init() { register(proto.KindDiskHealth, diskHealth) }

func diskHealth(ctx context.Context, _ json.RawMessage) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	h := proto.DiskHealth{Disks: []proto.PhysicalDisk{}}
	if exe, err := exec.LookPath("smartctl"); err == nil {
		smartDisks(ctx, exe, &h)
	} else {
		h.Errors = append(h.Errors, "smartctl is not installed (package smartmontools); disk health is unknown")
	}
	if b, err := os.ReadFile("/proc/mdstat"); err == nil {
		h.Arrays = parseMdstat(string(b))
	}
	return h, nil
}

type smartScan struct {
	Devices []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"devices"`
}

type smartInfo struct {
	Model       string `json:"model_name"`
	Serial      string `json:"serial_number"`
	Rotation    int    `json:"rotation_rate"`
	SmartStatus *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Capacity struct {
		Bytes int64 `json:"bytes"`
	} `json:"user_capacity"`
	Temperature struct {
		Current int `json:"current"`
	} `json:"temperature"`
	PowerOn struct {
		Hours int `json:"hours"`
	} `json:"power_on_time"`
	NVMe *struct {
		PercentageUsed int `json:"percentage_used"`
		MediaErrors    int `json:"media_errors"`
	} `json:"nvme_smart_health_information_log"`
	ATA *struct {
		Table []struct {
			ID  int `json:"id"`
			Raw struct {
				Value int `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	Device struct {
		Protocol string `json:"protocol"`
	} `json:"device"`
}

func smartDisks(ctx context.Context, exe string, h *proto.DiskHealth) {
	var scan smartScan
	out, _ := exec.CommandContext(ctx, exe, "--scan", "-j").Output() // #nosec G204 -- smartctl from PATH, fixed arguments
	if err := json.Unmarshal(out, &scan); err != nil {
		h.Errors = append(h.Errors, "smartctl --scan: "+err.Error())
		return
	}
	for _, d := range scan.Devices {
		// smartctl exits non-zero with bit flags for disk problems; the JSON
		// still has the details.
		out, _ := exec.CommandContext(ctx, exe, "-a", "-j", "-d", d.Type, d.Name).Output() // #nosec G204 -- device names from smartctl itself
		var s smartInfo
		if err := json.Unmarshal(out, &s); err != nil || s.Model == "" {
			continue
		}
		pd := proto.PhysicalDisk{Model: s.Model, Serial: s.Serial, Bus: s.Device.Protocol, SizeGB: int(s.Capacity.Bytes >> 30),
			TempC: s.Temperature.Current, PowerOnHours: s.PowerOn.Hours, Wear: -1, Health: proto.HealthUnknown}
		switch {
		case s.NVMe != nil:
			pd.Media, pd.Wear, pd.Errors = "SSD", s.NVMe.PercentageUsed, s.NVMe.MediaErrors
		case s.Rotation > 0:
			pd.Media = "HDD"
		case s.Rotation == 0 && s.ATA != nil:
			pd.Media = "SSD"
		}
		if s.ATA != nil {
			for _, a := range s.ATA.Table {
				if a.ID == 5 || a.ID == 197 || a.ID == 198 { // reallocated, pending, uncorrectable sectors
					pd.Errors += a.Raw.Value
				}
			}
		}
		if s.SmartStatus != nil {
			pd.Health = proto.HealthOK
			if !s.SmartStatus.Passed {
				pd.Health = proto.HealthFailing
			} else if pd.Errors > 0 || pd.Wear >= 90 {
				pd.Health = proto.HealthWarning
			}
		}
		h.Disks = append(h.Disks, pd)
	}
}

var (
	mdHeadRE  = regexp.MustCompile(`^(md[0-9a-z_]+)\s*:\s*(\S+)\s+(?:\(\S+\)\s+)?(raid[0-9]+|linear|multipath)?`)
	mdCountRE = regexp.MustCompile(`\[(\d+)/(\d+)\]\s+\[([U_]+)\]`)
)

// parseMdstat reads the arrays of /proc/mdstat.
func parseMdstat(s string) []proto.RAIDArray {
	var out []proto.RAIDArray
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		m := mdHeadRE.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		a := proto.RAIDArray{Name: m[1], Level: m[3], State: m[2], Health: proto.HealthOK}
		if m[2] != "active" {
			a.Health = proto.HealthFailing
		}
		for j := i + 1; j < len(lines) && j <= i+3 && strings.TrimSpace(lines[j]) != ""; j++ {
			if c := mdCountRE.FindStringSubmatch(lines[j]); c != nil && strings.Contains(c[3], "_") {
				a.Health, a.State = proto.HealthWarning, "degraded "+c[0]
			}
			if strings.Contains(lines[j], "recovery") || strings.Contains(lines[j], "resync") {
				a.State += ", rebuilding"
			}
		}
		out = append(out, a)
	}
	return out
}
