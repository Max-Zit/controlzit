package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T, names []string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		NotBefore: notBefore, NotAfter: notAfter}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

func TestParseKeyPair(t *testing.T) {
	now := time.Now()
	c, k := testCert(t, []string{"rmm.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	if _, err := ParseKeyPair(c, k, "rmm.example.com", now); err != nil {
		t.Fatalf("good pair: %v", err)
	}
	if _, err := ParseKeyPair(c, k, "other.example.com", now); err == nil || !strings.Contains(err.Error(), "not for other.example.com") {
		t.Fatalf("wrong name: %v", err)
	}
	_, k2 := testCert(t, []string{"rmm.example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
	if _, err := ParseKeyPair(c, k2, "rmm.example.com", now); err == nil {
		t.Fatal("a key of another certificate was accepted")
	}
	old, oldKey := testCert(t, []string{"rmm.example.com"}, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	if _, err := ParseKeyPair(old, oldKey, "rmm.example.com", now); err == nil || !strings.Contains(err.Error(), "not valid now") {
		t.Fatalf("expired: %v", err)
	}
	ipc, ipk := testCert(t, []string{"192.168.1.20"}, now.Add(-time.Hour), now.Add(time.Hour))
	if _, err := ParseKeyPair(ipc, ipk, "192.168.1.20", now); err != nil {
		t.Fatalf("certificate for an IP address: %v", err)
	}
	if _, err := ParseKeyPair([]byte("junk"), k, "rmm.example.com", now); err == nil {
		t.Fatal("junk accepted")
	}
}

func TestCertSettingsValidate(t *testing.T) {
	for _, c := range []struct {
		s  CertSettings
		ok bool
	}{
		{CertSettings{Mode: "self"}, true},
		{CertSettings{Mode: "upload", Hostname: "RMM.Example.com"}, true},
		{CertSettings{Mode: "upload", Hostname: "10.0.0.5"}, true},
		{CertSettings{Mode: "upload", Hostname: "not a name"}, false},
		{CertSettings{Mode: "acme", Hostname: "10.0.0.5", Challenge: "http", HTTP80: true}, false},
		{CertSettings{Mode: "acme", Hostname: "rmm.example.com", Challenge: "http"}, false}, // needs port 80
		{CertSettings{Mode: "acme", Hostname: "rmm.example.com", Challenge: "http", HTTP80: true}, true},
		{CertSettings{Mode: "acme", Hostname: "rmm.example.com", Challenge: "cloudflare", ACMEEmail: "x"}, false},
		{CertSettings{Mode: "other"}, false},
	} {
		if err := c.s.Validate(); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c.s, err)
		}
	}
}

func TestConsoleTLSSwitch(t *testing.T) {
	now := time.Now()
	sc, sk := testCert(t, []string{"self.local"}, now.Add(-time.Hour), now.Add(time.Hour))
	self, _ := tls.X509KeyPair(sc, sk)
	dir := t.TempDir()
	ct := NewConsoleTLS(dir, self, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !ct.Info().Self {
		t.Fatal("starts with its own certificate")
	}
	c, k := testCert(t, []string{"rmm.example.com"}, now.Add(-time.Hour), now.Add(60*24*time.Hour))
	if err := ct.Install(c, k); err != nil {
		t.Fatal(err)
	}
	got, _ := ct.GetCertificate(nil)
	x, _ := x509.ParseCertificate(got.Certificate[0])
	if x.Subject.CommonName != "rmm.example.com" || ct.Info().Self || ct.Info().DaysLeft() < 58 {
		t.Fatalf("installed certificate not served: %s", x.Subject.CommonName)
	}
	// It survives a restart.
	again := NewConsoleTLS(dir, self, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if again.Info().Self {
		t.Fatal("saved certificate not loaded")
	}
	if err := again.UseSelf(); err != nil || !again.Info().Self {
		t.Fatalf("back to its own certificate: %v", err)
	}
	if NewConsoleTLS(dir, self, slog.New(slog.NewTextHandler(io.Discard, nil))).Info().Self != true {
		t.Fatal("removed certificate still loaded")
	}
}

func TestPort80(t *testing.T) {
	now := time.Now()
	sc, sk := testCert(t, []string{"self.local"}, now.Add(-time.Hour), now.Add(time.Hour))
	self, _ := tls.X509KeyPair(sc, sk)
	ct := NewConsoleTLS(t.TempDir(), self, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ct.Redirect = func(host string) string { return "https://" + host + ":8443/" }
	ct.tokens["tok123"] = "tok123.keyauth"
	srv := httptest.NewServer(http.HandlerFunc(ct.serve80))
	defer srv.Close()
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noFollow.Get(srv.URL + "/.well-known/acme-challenge/tok123")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "tok123.keyauth" {
		t.Fatalf("challenge answer %q", b)
	}
	resp, _ = noFollow.Get(srv.URL + "/.well-known/acme-challenge/other")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown token: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/devices", nil)
	req.Host = "rmm.example.com"
	resp, _ = noFollow.Do(req)
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "https://rmm.example.com:8443/" {
		t.Fatalf("redirect: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	req.Host = "evil<script>"
	resp, _ = noFollow.Do(req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad host redirected: %d", resp.StatusCode)
	}
}
