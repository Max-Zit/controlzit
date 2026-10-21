// Package proto defines the messages between the ControlZit agent and
// server.
//
// Enrollment: the agent creates an ed25519 key and a self-signed client
// certificate for it, then POSTs EnrollRequest to /agent/v1/enroll over
// TLS, presenting that certificate and pinning the server's agent
// certificate (SHA-256 fingerprint given at install). The server consumes
// the enrollment token and remembers the key; from then on the TLS client
// certificate is the agent's identity.
//
// Channel: the agent opens a WebSocket at /agent/v1/connect (same TLS
// identity) and keeps it open; both sides send Envelope messages.
package proto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// Version of the protocol; the server refuses agents it does not know.
const Version = 1

// Paths on the agent endpoint.
const (
	PathEnroll  = "/agent/v1/enroll"
	PathConnect = "/agent/v1/connect"
	PathHealth  = "/agent/v1/health"
)

// Message types.
const (
	TypeHello            = "hello"             // agent → server, first message
	TypeWelcome          = "welcome"           // server → agent, answer to hello
	TypeHeartbeat        = "heartbeat"         // agent → server
	TypeInventory        = "inventory"         // agent → server
	TypeInventoryRequest = "inventory.request" // server → agent
)

// Limits.
const (
	MaxEnrollBody  = 64 << 10
	MaxMessageSize = 8 << 20
)

// EnrollRequest is the body of the enrollment.
type EnrollRequest struct {
	Protocol     int    `json:"protocol"`
	Token        string `json:"token"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	AgentVersion string `json:"agent_version"`
}

// EnrollResponse confirms the enrollment.
type EnrollResponse struct {
	AgentID  string `json:"agent_id"`
	DeviceID int64  `json:"device_id"`
	Customer string `json:"customer"`
	Site     string `json:"site"`
}

// Error is the JSON body of a failed agent request.
type Error struct {
	Error string `json:"error"`
}

// Envelope wraps every channel message.
type Envelope struct {
	Type string          `json:"t"`
	Data json.RawMessage `json:"d,omitempty"`
}

// Hello introduces a connecting agent.
type Hello struct {
	Protocol     int       `json:"protocol"`
	AgentVersion string    `json:"agent_version"`
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`
	OSVersion    string    `json:"os_version"`
	OSBuild      string    `json:"os_build"`
	BootTime     time.Time `json:"boot_time"`
	LoggedOnUser string    `json:"logged_on_user"`
}

// Welcome tells the agent how often to report.
type Welcome struct {
	DeviceID         int64 `json:"device_id"`
	HeartbeatSeconds int   `json:"heartbeat_seconds"`
	InventoryHours   int   `json:"inventory_hours"`
}

// Heartbeat is the periodic sign of life.
type Heartbeat struct {
	BootTime     time.Time `json:"boot_time"`
	LoggedOnUser string    `json:"logged_on_user"`
}

// Inventory describes a machine.
type Inventory struct {
	CollectedAt   time.Time    `json:"collected_at"`
	Hostname      string       `json:"hostname"`
	Domain        string       `json:"domain"`
	PartOfDomain  bool         `json:"part_of_domain"`
	OS            OSInfo       `json:"os"`
	Hardware      Hardware     `json:"hardware"`
	Disks         []Disk       `json:"disks"`
	Network       []NetAdapter `json:"network"`
	Software      []Software   `json:"software"`
	LoggedOnUser  string       `json:"logged_on_user"`
	BitLocker     []BitLocker  `json:"bitlocker"`
	Defender      *Defender    `json:"defender,omitempty"`
	Firewall      []Firewall   `json:"firewall"`
	PendingReboot bool         `json:"pending_reboot"`
	// Errors are the parts that could not be collected.
	Errors []string `json:"errors,omitempty"`
}

// OSInfo is the operating system.
type OSInfo struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Build       string    `json:"build"`
	DisplayVer  string    `json:"display_version"` // e.g. 24H2
	Arch        string    `json:"arch"`
	InstallDate time.Time `json:"install_date"`
	BootTime    time.Time `json:"boot_time"`
}

// Hardware is the computer itself.
type Hardware struct {
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	Serial       string `json:"serial"`
	BIOS         string `json:"bios"`
	CPU          string `json:"cpu"`
	Cores        int    `json:"cores"`
	Threads      int    `json:"threads"`
	MemoryBytes  uint64 `json:"memory_bytes"`
	Virtual      bool   `json:"virtual"`
}

// Disk is a fixed volume.
type Disk struct {
	Drive string `json:"drive"`
	Label string `json:"label"`
	FS    string `json:"fs"`
	Size  uint64 `json:"size"`
	Free  uint64 `json:"free"`
}

// NetAdapter is an enabled network adapter.
type NetAdapter struct {
	Name     string   `json:"name"`
	MAC      string   `json:"mac"`
	IPs      []string `json:"ips"`
	Gateways []string `json:"gateways"`
	DNS      []string `json:"dns"`
	DHCP     bool     `json:"dhcp"`
}

// Software is an installed program.
type Software struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	InstallDate string `json:"install_date"`
}

// BitLocker is the encryption state of a volume.
type BitLocker struct {
	Drive      string `json:"drive"`
	Protection string `json:"protection"` // on, off, unknown
	Status     string `json:"status"`     // fully encrypted, decrypted, encrypting …
}

// Defender is the Microsoft Defender state.
type Defender struct {
	Antivirus        bool      `json:"antivirus"`
	RealTime         bool      `json:"real_time"`
	Tamper           bool      `json:"tamper"`
	SignatureVersion string    `json:"signature_version"`
	SignatureUpdated time.Time `json:"signature_updated"`
}

// Firewall is a Windows Firewall profile.
type Firewall struct {
	Profile string `json:"profile"`
	Enabled bool   `json:"enabled"`
}

// KeyID is the stored identity of an agent key: SHA-256 of the raw public key.
func KeyID(pub []byte) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

// NormalizeFingerprint accepts "AB:CD…" or "abcd…" forms.
func NormalizeFingerprint(s string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s)))
}

// EnrollCodePrefix marks an enrollment code: everything an installer needs
// (server address, certificate fingerprint, token) in one string.
const EnrollCodePrefix = "CZ1-"

// EnrollData is what an enrollment code carries.
type EnrollData struct {
	Server      string `json:"u"`
	Fingerprint string `json:"f"`
	Token       string `json:"t"`
}

// MakeEnrollCode encodes the data as CZ1-<base64url JSON>.
func MakeEnrollCode(d EnrollData) string {
	b, _ := json.Marshal(d)
	return EnrollCodePrefix + base64.RawURLEncoding.EncodeToString(b)
}
