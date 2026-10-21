package agent

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
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

func TestEnrollCode(t *testing.T) {
	d := EnrollData{Server: "https://rmm.example.com:8444/", Fingerprint: strings.Repeat("AB", 32), Token: "czet_x"}
	code := MakeEnrollCode(d)
	if !strings.HasPrefix(code, "CZ1-") || strings.ContainsAny(code, "+/= ") {
		t.Fatalf("code %q", code)
	}
	got, err := ParseEnrollCode(" " + code + "\n")
	if err != nil || got.Server != "https://rmm.example.com:8444" || got.Fingerprint != strings.Repeat("ab", 32) || got.Token != "czet_x" {
		t.Fatalf("parse: %+v %v", got, err)
	}
	for _, bad := range []string{"", "CZ1-", "CZ1-!!!", "BZ1-abc", MakeEnrollCode(EnrollData{Server: "http://x:1", Fingerprint: d.Fingerprint, Token: "t"})} {
		if _, err := ParseEnrollCode(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPendingAndForget(t *testing.T) {
	ProtectDir = func(string) error { return nil }
	dir := t.TempDir()
	d := EnrollData{Server: "https://rmm:8444", Fingerprint: strings.Repeat("ab", 32), Token: "czet_y"}
	if err := SavePending(dir, d); err != nil {
		t.Fatal(err)
	}
	if got, ok := LoadPending(dir); !ok || got.Token != "czet_y" {
		t.Fatal("pending not loaded")
	}
	if _, err := LoadOrCreateKey(dir); err != nil {
		t.Fatal(err)
	}
	if err := Forget(dir); err != nil {
		t.Fatal(err)
	}
	if _, ok := LoadPending(dir); ok {
		t.Fatal("pending survived forget")
	}
}

func TestSetAsideRestore(t *testing.T) {
	ProtectDir = func(string) error { return nil }
	dir := t.TempDir()
	k1, _ := LoadOrCreateKey(dir)
	c := &Config{ServerURL: "https://a:1", Fingerprint: strings.Repeat("ab", 32), AgentID: "x"}
	c.Save(dir)
	restore, err := SetAside(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(dir); err == nil {
		t.Fatal("config still in place")
	}
	LoadOrCreateKey(dir) // a failed enrollment made a new key
	restore()
	k2, _ := LoadOrCreateKey(dir)
	if got, err := LoadConfig(dir); err != nil || got.AgentID != "x" || !k1.Equal(k2) {
		t.Fatal("old enrollment not restored")
	}
}

func TestRedact(t *testing.T) {
	got := redact(json.RawMessage(`{"session":"s1","token":"secret-token","technician":"ana"}`))
	if strings.Contains(got, "secret-token") || !strings.Contains(got, "s1") {
		t.Fatalf("redact: %s", got)
	}
}
