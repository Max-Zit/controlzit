package proto

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// Network checks: an agent pings an address, connects to a TCP port or
// fetches a web address, from its own network, when the server asks
// (every minute for the checks of its policy).
const KindNetCheck = "net.check"

// Network check kinds.
const (
	NetPing = "ping"
	NetTCP  = "tcp"
	NetHTTP = "http"
)

// NetCheck is one check.
type NetCheck struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Target string `json:"target"`         // host name or IP address; for http a URL
	Port   int    `json:"port,omitempty"` // tcp
}

var netHostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.\-:%]{0,252}[A-Za-z0-9\]])?$`)

// MaxNetChecks is how many checks a device runs.
const MaxNetChecks = 20

// Valid checks a network check before it is stored or run.
func (c *NetCheck) Valid() error {
	if n := strings.TrimSpace(c.Name); n == "" || len(n) > 60 {
		return errors.New("each network check needs a name of up to 60 characters")
	}
	switch c.Kind {
	case NetPing, NetTCP:
		if !netHostRE.MatchString(strings.Trim(c.Target, "[]")) {
			return errors.New("enter a host name or an IP address")
		}
		if c.Kind == NetTCP && (c.Port < 1 || c.Port > 65535) {
			return errors.New("a TCP check needs a port 1–65535")
		}
	case NetHTTP:
		u, err := url.Parse(c.Target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || len(c.Target) > 500 {
			return errors.New("a web check needs an address that starts with http:// or https://")
		}
	default:
		return errors.New("unknown kind of network check")
	}
	return nil
}

// NetCheckRun is the argument of net.check.
type NetCheckRun struct {
	Checks []NetCheck `json:"checks"`
}

// NetCheckResult is how one check went.
type NetCheckResult struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	MS       int    `json:"ms"`                  // response time
	Error    string `json:"error,omitempty"`     // why it failed
	CertDays int    `json:"cert_days,omitempty"` // https: days until the certificate expires
}

// NetCheckResults is the answer of net.check.
type NetCheckResults struct {
	Results []NetCheckResult `json:"results"`
}

// Disk health: the physical disks with what they report about themselves
// (SMART, Windows storage reliability counters) and the RAID arrays the
// system manages (Storage Spaces, Linux md). Hardware RAID controllers hide
// their disks and are not covered.
const KindDiskHealth = "disk.health"

// Disk health states.
const (
	HealthOK      = "ok"
	HealthWarning = "warning"
	HealthFailing = "failing"
	HealthUnknown = "unknown"
)

// PhysicalDisk is one disk.
type PhysicalDisk struct {
	Model        string `json:"model"`
	Serial       string `json:"serial,omitempty"`
	Media        string `json:"media,omitempty"` // SSD, HDD
	Bus          string `json:"bus,omitempty"`
	SizeGB       int    `json:"size_gb,omitempty"`
	Health       string `json:"health"`
	Status       string `json:"status,omitempty"`
	TempC        int    `json:"temp_c,omitempty"`
	Wear         int    `json:"wear"` // percent of the rated life used; -1 unknown
	PowerOnHours int    `json:"power_on_hours,omitempty"`
	Errors       int    `json:"errors,omitempty"` // uncorrected errors, reallocated or pending sectors
}

// RAIDArray is a software RAID or Storage Spaces disk.
type RAIDArray struct {
	Name   string `json:"name"`
	Level  string `json:"level,omitempty"`
	Health string `json:"health"` // ok, warning (degraded, rebuilding), failing
	State  string `json:"state,omitempty"`
}

// DiskHealth is the answer of disk.health.
type DiskHealth struct {
	Disks  []PhysicalDisk `json:"disks"`
	Arrays []RAIDArray    `json:"arrays,omitempty"`
	Errors []string       `json:"errors,omitempty"`
}
