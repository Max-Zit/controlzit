package agent

import (
	"crypto/ed25519"
	"crypto/x509"
	"strings"
	"testing"
)

func TestCheckServerURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://rmm.example.com:8444":  "https://rmm.example.com:8444",
		"https://rmm.example.com:8444/": "https://rmm.example.com:8444",
		" https://10.0.0.5:8444 ":       "https://10.0.0.5:8444",
	} {
		if got, err := CheckServerURL(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"http://rmm:8444", "rmm:8444", "https://user@rmm:8444", "https://rmm:8444/x", "https://rmm:8444?a=1"} {
		if _, err := CheckServerURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCheckFingerprint(t *testing.T) {
	f := strings.Repeat("Ab", 32)
	if got, err := CheckFingerprint(f); err != nil || got != strings.ToLower(f) {
		t.Fatal(got, err)
	}
	colons := strings.TrimSuffix(strings.Repeat("AB:", 32), ":")
	if _, err := CheckFingerprint(colons); err != nil {
		t.Fatal("colon form rejected")
	}
	for _, bad := range []string{"", "abc", strings.Repeat("zz", 32), strings.Repeat("ab", 33)} {
		if _, err := CheckFingerprint(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestKeyPersists(t *testing.T) {
	ProtectDir = func(string) error { return nil }
	dir := t.TempDir()
	k1, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadOrCreateKey(dir)
	if err != nil || !k1.Equal(k2) {
		t.Fatal("key not reloaded")
	}
	c, err := clientCert(k1)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil || !leaf.PublicKey.(ed25519.PublicKey).Equal(k1.Public()) {
		t.Fatal("client certificate key mismatch", err)
	}
}
