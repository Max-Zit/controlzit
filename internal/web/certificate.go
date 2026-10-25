package web

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/max-zit/controlzit/internal/tlsutil"
)

// Console certificate (Settings → Certificate). The console port serves
// its own self-signed certificate until the administrator uploads one or
// lets the server get one from Let's Encrypt. The agent port always keeps
// its own certificate: agents pin it, so a new console certificate never
// cuts them off. Port 80 can answer Let's Encrypt and send browsers on to
// HTTPS.

const settingCert = "certificate"

// CertSettings are saved in the database (the Cloudflare token sealed).
type CertSettings struct {
	Mode            string `json:"mode"` // self, upload, acme
	Hostname        string `json:"hostname,omitempty"`
	ACMEEmail       string `json:"acme_email,omitempty"`
	Challenge       string `json:"challenge,omitempty"` // http, cloudflare
	CloudflareToken string `json:"cloudflare_token,omitempty"`
	// HTTP80 serves port 80: Let's Encrypt HTTP challenges and a redirect
	// to the console.
	HTTP80 bool `json:"http80,omitempty"`
	// ACMEDirectory overrides Let's Encrypt (tests, staging).
	ACMEDirectory string `json:"acme_directory,omitempty"`
}

const letsEncryptURL = "https://acme-v02.api.letsencrypt.org/directory"

var dnsNameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// Validate checks the settings (the token is checked when used).
func (c *CertSettings) Validate() error {
	c.Hostname = strings.ToLower(strings.TrimSpace(c.Hostname))
	switch c.Mode {
	case "self":
		return nil
	case "upload":
		if net.ParseIP(c.Hostname) == nil && !dnsNameRe.MatchString(c.Hostname) {
			return uiErr("Enter the DNS name or IP address browsers use for the console, e.g. rmm.example.com.")
		}
	case "acme":
		if !dnsNameRe.MatchString(c.Hostname) {
			return uiErr("Let's Encrypt needs the public DNS name of the console, e.g. rmm.example.com.")
		}
		if c.ACMEEmail != "" && !strings.Contains(c.ACMEEmail, "@") {
			return uiErr("Enter a valid email address.")
		}
		switch c.Challenge {
		case "http":
			if !c.HTTP80 {
				return uiErr("The HTTP check needs port 80: switch on \"Answer on port 80\".")
			}
		case "cloudflare":
		default:
			return uiErr("Choose how Let's Encrypt checks the name.")
		}
	default:
		return uiErr("Unknown certificate mode.")
	}
	return nil
}

// CertInfo describes a certificate for the page.
type CertInfo struct {
	Subject  string
	Issuer   string
	Names    []string
	NotAfter time.Time
	Self     bool // the console's own certificate
}

// DaysLeft until the certificate expires.
func (c *CertInfo) DaysLeft() int { return int(time.Until(c.NotAfter).Hours() / 24) }

// ConsoleTLS serves the console certificate and port 80.
type ConsoleTLS struct {
	dir  string // <data-dir>/tls/web
	log  *slog.Logger
	self tls.Certificate

	mu      sync.RWMutex
	cur     *tls.Certificate // uploaded or from Let's Encrypt
	tokens  map[string]string
	http80  *http.Server
	lastErr string
	// Redirect is where port 80 sends browsers (set by the server).
	Redirect func(host string) string
}

// NewConsoleTLS loads a saved certificate from dir, if there is one.
func NewConsoleTLS(dir string, self tls.Certificate, log *slog.Logger) *ConsoleTLS {
	t := &ConsoleTLS{dir: dir, self: self, log: log, tokens: map[string]string{}}
	if c, err := tls.LoadX509KeyPair(t.certFile(), t.keyFile()); err == nil {
		t.cur = &c
	}
	return t
}

func (t *ConsoleTLS) certFile() string { return filepath.Join(t.dir, "cert.pem") }
func (t *ConsoleTLS) keyFile() string  { return filepath.Join(t.dir, "key.pem") }

// GetCertificate is the tls.Config callback of the console listener.
func (t *ConsoleTLS) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.cur != nil {
		return t.cur, nil
	}
	return &t.self, nil
}

// Config is the TLS configuration of the console listener.
func (t *ConsoleTLS) Config() *tls.Config {
	cfg := tlsutil.ServerConfig(t.self)
	cfg.Certificates = nil
	cfg.GetCertificate = t.GetCertificate
	return cfg
}

// Info describes the certificate browsers get now.
func (t *ConsoleTLS) Info() *CertInfo {
	t.mu.RLock()
	c, self := t.cur, false
	t.mu.RUnlock()
	if c == nil {
		c, self = &t.self, true
	}
	x, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil
	}
	names := append([]string{}, x.DNSNames...)
	for _, ip := range x.IPAddresses {
		names = append(names, ip.String())
	}
	return &CertInfo{Subject: x.Subject.CommonName, Issuer: x.Issuer.CommonName, Names: names, NotAfter: x.NotAfter, Self: self}
}

// LastError is the last failure to get or renew a certificate.
func (t *ConsoleTLS) LastError() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.lastErr
}

func (t *ConsoleTLS) setErr(s string) {
	t.mu.Lock()
	t.lastErr = s
	t.mu.Unlock()
}

// UseSelf goes back to the console's own certificate.
func (t *ConsoleTLS) UseSelf() error {
	t.mu.Lock()
	t.cur = nil
	t.lastErr = ""
	t.mu.Unlock()
	for _, f := range []string{t.certFile(), t.keyFile()} {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// ParseKeyPair checks an uploaded certificate (PEM chain) and key: they
// belong together, the certificate is valid now and names hostname.
func ParseKeyPair(certPEM, keyPEM []byte, hostname string, now time.Time) (*tls.Certificate, error) {
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, uiErr("The certificate and the private key do not fit together or are not PEM files: " + err.Error())
	}
	x, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil, err
	}
	if now.Before(x.NotBefore) || now.After(x.NotAfter) {
		return nil, uiErrf("The certificate is not valid now (valid %s – %s).", x.NotBefore.Format("2006-01-02"), x.NotAfter.Format("2006-01-02"))
	}
	if err := x.VerifyHostname(hostname); err != nil {
		return nil, uiErrf("The certificate is not for %s (it names %s).", hostname, strings.Join(append(x.DNSNames, ipStrings(x.IPAddresses)...), ", "))
	}
	return &c, nil
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// Install saves and serves a certificate.
func (t *ConsoleTLS) Install(certPEM, keyPEM []byte) error {
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(t.dir, 0o700); err != nil {
		return err
	}
	if err := writeFileAtomic(t.keyFile(), keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(t.certFile(), certPEM, 0o644); err != nil {
		return err
	}
	t.mu.Lock()
	t.cur = &c
	t.lastErr = ""
	t.mu.Unlock()
	return nil
}

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---- port 80

// ServeHTTP80 starts or stops the port 80 listener.
func (t *ConsoleTLS) ServeHTTP80(on bool, addr string) error {
	t.mu.Lock()
	old := t.http80
	t.http80 = nil
	t.mu.Unlock()
	if old != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = old.Shutdown(ctx)
		cancel()
	}
	if !on {
		return nil
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("port 80: %w", err)
	}
	hs := &http.Server{Handler: http.HandlerFunc(t.serve80), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
	t.mu.Lock()
	t.http80 = hs
	t.mu.Unlock()
	go func() {
		if err := hs.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.log.Warn("port 80 stopped", "err", err)
		}
	}()
	return nil
}

func (t *ConsoleTLS) serve80(w http.ResponseWriter, r *http.Request) {
	const prefix = "/.well-known/acme-challenge/"
	if strings.HasPrefix(r.URL.Path, prefix) {
		t.mu.RLock()
		v, ok := t.tokens[strings.TrimPrefix(r.URL.Path, prefix)]
		t.mu.RUnlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, v)
		return
	}
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	if t.Redirect == nil || (net.ParseIP(host) == nil && !dnsNameRe.MatchString(strings.ToLower(host))) {
		http.Error(w, "use HTTPS", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, t.Redirect(host), http.StatusMovedPermanently)
}

// ---- Let's Encrypt

func (t *ConsoleTLS) accountKey() (crypto.Signer, error) {
	p := filepath.Join(t.dir, "acme-account.key")
	if b, err := os.ReadFile(p); err == nil { // #nosec G304 -- our own data directory
		if blk, _ := pem.Decode(b); blk != nil {
			if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
				return k, nil
			}
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(t.dir, 0o700); err != nil {
		return nil, err
	}
	return k, writeFileAtomic(p, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}

// Obtain gets a certificate from Let's Encrypt and serves it.
func (t *ConsoleTLS) Obtain(ctx context.Context, c CertSettings, hc *http.Client) error {
	err := t.obtain(ctx, c, hc)
	if err != nil {
		t.setErr(err.Error())
	}
	return err
}

func (t *ConsoleTLS) obtain(ctx context.Context, c CertSettings, hc *http.Client) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	key, err := t.accountKey()
	if err != nil {
		return err
	}
	dir := c.ACMEDirectory
	if dir == "" {
		dir = letsEncryptURL
	}
	cl := &acme.Client{Key: key, DirectoryURL: dir, HTTPClient: hc, UserAgent: "ControlZit"}
	acct := &acme.Account{}
	if c.ACMEEmail != "" {
		acct.Contact = []string{"mailto:" + c.ACMEEmail}
	}
	if _, err := cl.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return uiErrf("Let's Encrypt account: %w", err)
	}
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(c.Hostname))
	if err != nil {
		return uiErrf("Let's Encrypt order: %w", err)
	}
	for _, u := range order.AuthzURLs {
		z, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			return err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		if err := t.solve(ctx, cl, c, z, hc); err != nil {
			return err
		}
	}
	if order, err = cl.WaitOrder(ctx, order.URI); err != nil {
		return uiErrf("Let's Encrypt order: %w", err)
	}
	ck, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: c.Hostname}, DNSNames: []string{c.Hostname}}, ck)
	if err != nil {
		return err
	}
	chain, _, err := cl.CreateCertFromOrder(ctx, order, csr, true)
	if err != nil {
		return uiErrf("Let's Encrypt certificate: %w", err)
	}
	var certPEM bytes.Buffer
	for _, der := range chain {
		_ = pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	kder, err := x509.MarshalECPrivateKey(ck)
	if err != nil {
		return err
	}
	if err := t.Install(certPEM.Bytes(), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})); err != nil {
		return err
	}
	t.log.Info("certificate from Let's Encrypt installed", "host", c.Hostname)
	return nil
}

func (t *ConsoleTLS) solve(ctx context.Context, cl *acme.Client, c CertSettings, z *acme.Authorization, hc *http.Client) error {
	want := "http-01"
	if c.Challenge == "cloudflare" {
		want = "dns-01"
	}
	var ch *acme.Challenge
	for _, x := range z.Challenges {
		if x.Type == want {
			ch = x
		}
	}
	if ch == nil {
		return uiErrf("Let's Encrypt does not offer the %s check for %s", want, z.Identifier.Value)
	}
	switch want {
	case "http-01":
		v, err := cl.HTTP01ChallengeResponse(ch.Token)
		if err != nil {
			return err
		}
		t.mu.Lock()
		t.tokens[ch.Token] = v
		t.mu.Unlock()
		defer func() {
			t.mu.Lock()
			delete(t.tokens, ch.Token)
			t.mu.Unlock()
		}()
	case "dns-01":
		v, err := cl.DNS01ChallengeRecord(ch.Token)
		if err != nil {
			return err
		}
		cf := cloudflare{token: c.CloudflareToken, hc: hc}
		zone, id, err := cf.addTXT(ctx, "_acme-challenge."+z.Identifier.Value, v)
		if err != nil {
			return uiErrf("Cloudflare: %w", err)
		}
		defer func() { _ = cf.remove(context.WithoutCancel(ctx), zone, id) }()
		select { // let the record reach the name servers
		case <-time.After(dnsWait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if _, err := cl.Accept(ctx, ch); err != nil {
		return err
	}
	if _, err := cl.WaitAuthorization(ctx, z.URI); err != nil {
		return uiErrf("Let's Encrypt could not check %s: %w", z.Identifier.Value, err)
	}
	return nil
}

var dnsWait = 20 * time.Second

// NeedsRenewal reports whether a certificate from Let's Encrypt expires
// within 30 days (or there is none yet).
func (t *ConsoleTLS) NeedsRenewal() bool {
	i := t.Info()
	return i == nil || i.Self || time.Until(i.NotAfter) < 30*24*time.Hour
}

// ---- Cloudflare DNS (for the dns-01 check)

type cloudflare struct {
	token string
	hc    *http.Client
	base  string // tests
}

func (c cloudflare) do(ctx context.Context, method, path string, body, out any) error {
	base := c.base
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var env struct {
		Success bool                       `json:"success"`
		Errors  []struct{ Message string } `json:"errors"`
		Result  json.RawMessage            `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&env); err != nil {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if !env.Success {
		msg := "HTTP " + strconv.Itoa(resp.StatusCode)
		if len(env.Errors) > 0 {
			msg = env.Errors[0].Message
		}
		return errors.New(msg)
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// zone finds the zone of name by trying its parent domains.
func (c cloudflare) zone(ctx context.Context, name string) (string, error) {
	labels := strings.Split(name, ".")
	for i := 0; i+2 <= len(labels); i++ {
		var zs []struct{ ID string }
		if err := c.do(ctx, http.MethodGet, "/zones?name="+strings.Join(labels[i:], "."), nil, &zs); err != nil {
			return "", err
		}
		if len(zs) > 0 {
			return zs[0].ID, nil
		}
	}
	return "", fmt.Errorf("no Cloudflare zone for %s (check the token's Zone:DNS:Edit permission)", name)
}

func (c cloudflare) addTXT(ctx context.Context, name, value string) (zone, id string, err error) {
	if zone, err = c.zone(ctx, name); err != nil {
		return "", "", err
	}
	var rec struct{ ID string }
	err = c.do(ctx, http.MethodPost, "/zones/"+zone+"/dns_records", map[string]any{"type": "TXT", "name": name, "content": value, "ttl": 60}, &rec)
	return zone, rec.ID, err
}

func (c cloudflare) remove(ctx context.Context, zone, id string) error {
	return c.do(ctx, http.MethodDelete, "/zones/"+zone+"/dns_records/"+id, nil, nil)
}

// Port80 reports whether the port 80 listener runs.
func (t *ConsoleTLS) Port80() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.http80 != nil
}
