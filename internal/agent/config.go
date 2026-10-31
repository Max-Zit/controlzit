// Package agent is the RMMZit agent: it enrolls with a server, keeps
// an outbound channel open and reports status and inventory.
package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
)

// Version is set at build time.
var Version = "dev"

// Config is the agent's state on disk (agent.json).
type Config struct {
	// ServerURL is the agent endpoint, e.g. https://rmm.example.com:8444.
	ServerURL string `json:"server_url"`
	// Fingerprint is the pinned SHA-256 of the server's agent certificate.
	Fingerprint string    `json:"fingerprint"`
	AgentID     string    `json:"agent_id"`
	DeviceID    int64     `json:"device_id"`
	Customer    string    `json:"customer"`
	Site        string    `json:"site"`
	EnrolledAt  time.Time `json:"enrolled_at"`
	// CommandKey is the server's ed25519 key; only commands signed with it run.
	CommandKey []byte `json:"command_key,omitempty"`
}

// Files in the data directory.
const (
	configFile = "agent.json"
	keyFile    = "agent.key"
	LogFile    = "agent.log"
)

// DefaultDir is the agent's data directory.
func DefaultDir() string {
	return currentDir(newDir())
}

func newDir() string {
	if runtime.GOOS == "windows" {
		if p := os.Getenv("ProgramData"); p != "" {
			return filepath.Join(p, "RMMZit Agent")
		}
		return `C:\ProgramData\RMMZit Agent`
	}
	return "/var/lib/rmmzit-agent"
}

// EnsureDir creates the data directory, readable only by SYSTEM and
// administrators (root on other systems): it holds the agent's private key.
func EnsureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return ProtectDir(dir)
}

// ProtectDir restricts the data directory; tests replace it, because the
// test user would lock itself out.
var ProtectDir = protectDir

// LoadConfig reads agent.json; ErrNotEnrolled when it does not exist.
func LoadConfig(dir string) (*Config, error) {
	b, err := os.ReadFile(filepath.Join(dir, configFile)) // #nosec G304 -- fixed name in the data directory
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("%s: %w", configFile, err)
	}
	if c.ServerURL == "" || c.Fingerprint == "" || c.AgentID == "" {
		return nil, fmt.Errorf("%s is incomplete; enroll the agent again", configFile)
	}
	return c, nil
}

// ErrNotEnrolled means the agent has no configuration yet.
var ErrNotEnrolled = errors.New("the agent is not enrolled yet")

// Save writes agent.json atomically.
func (c *Config) Save(dir string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, configFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, configFile))
}

// CheckServerURL validates the agent endpoint address.
func CheckServerURL(s string) (string, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(s), "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.User != nil || u.RawQuery != "" {
		return "", errors.New("the server address must look like https://rmm.example.com:8444")
	}
	return "https://" + u.Host, nil
}

// CheckFingerprint validates a SHA-256 fingerprint (64 hex digits).
func CheckFingerprint(s string) (string, error) {
	f := proto.NormalizeFingerprint(s)
	if len(f) != 64 || strings.Trim(f, "0123456789abcdef") != "" {
		return "", errors.New("the server fingerprint must be 64 hexadecimal digits (SHA-256)")
	}
	return f, nil
}

// LoadOrCreateKey returns the agent's ed25519 key, creating it once.
func LoadOrCreateKey(dir string) (ed25519.PrivateKey, error) {
	p := filepath.Join(dir, keyFile)
	b, err := os.ReadFile(p) // #nosec G304 -- fixed name in the data directory
	if err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("%s is damaged", p)
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		ek, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s is not an ed25519 key", p)
		}
		return ek, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

// clientCert is a self-signed certificate for the agent key; only the
// key matters to the server.
func clientCert(priv ed25519.PrivateKey) (tls.Certificate, error) {
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rmmzit-agent"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(30, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}
