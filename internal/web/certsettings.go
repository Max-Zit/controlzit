package web

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Settings → Certificate.

// Cert loads the certificate settings (the Cloudflare token stays sealed).
func (s *Server) Cert(ctx context.Context) CertSettings {
	c := CertSettings{Mode: "self"}
	_ = s.store.GetSetting(ctx, settingCert, &c)
	return c
}

func (s *Server) certToken(c CertSettings) string {
	if c.CloudflareToken == "" {
		return ""
	}
	t, err := s.store.OpenSecret("settings.certificate.cloudflare", c.CloudflareToken)
	if err != nil {
		return ""
	}
	return t
}

type certData struct {
	S        CertSettings
	Info     *CertInfo
	Err      string
	HasToken bool
	Port80   bool // the port 80 listener runs
}

func (s *Server) handleCertSettings(w http.ResponseWriter, r *http.Request) {
	c := s.Cert(r.Context())
	d := &certData{S: c, Info: s.TLS.Info(), Err: s.TLS.LastError(), HasToken: c.CloudflareToken != "", Port80: s.TLS.Port80()}
	d.S.CloudflareToken = ""
	s.render(w, r, http.StatusOK, "certificate", &Page{Title: "Certificate", Nav: "settings", Data: d})
}

// readPEM reads an uploaded file or the pasted text of a field.
func readPEM(r *http.Request, name string) []byte {
	if f, _, err := r.FormFile(name + "_file"); err == nil {
		defer f.Close()
		b, _ := io.ReadAll(io.LimitReader(f, 256<<10))
		if len(b) > 0 {
			return b
		}
	}
	return []byte(strings.TrimSpace(r.FormValue(name)))
}

func (s *Server) handleCertSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		s.redirect(w, r, "/settings/certificate", "The upload is too large.")
		return
	}
	ctx := r.Context()
	old := s.Cert(ctx)
	c := CertSettings{Mode: r.FormValue("mode"), Hostname: r.FormValue("hostname"), ACMEEmail: strings.TrimSpace(r.FormValue("acme_email")),
		Challenge: r.FormValue("challenge"), HTTP80: r.FormValue("http80") == "1", ACMEDirectory: old.ACMEDirectory, CloudflareToken: old.CloudflareToken}
	if t := strings.TrimSpace(r.FormValue("cloudflare_token")); t != "" {
		c.CloudflareToken = s.store.SealSecret("settings.certificate.cloudflare", t)
	}
	if err := c.Validate(); err != nil {
		s.redirectErr(w, r, "/settings/certificate", err)
		return
	}
	if c.Mode == "acme" && c.Challenge == "cloudflare" && c.CloudflareToken == "" {
		s.redirect(w, r, "/settings/certificate", "Enter a Cloudflare API token with the Zone:DNS:Edit permission.")
		return
	}
	if c.Mode != "acme" || c.Challenge != "cloudflare" {
		c.CloudflareToken = "" // not kept when not used
	}
	var detail string
	switch c.Mode {
	case "self":
		if err := s.TLS.UseSelf(); err != nil {
			s.serverError(w, r, err)
			return
		}
		detail = "the console's own certificate"
	case "upload":
		certPEM, keyPEM := readPEM(r, "cert"), readPEM(r, "key")
		if len(certPEM) == 0 && old.Mode == "upload" && !s.TLS.Info().Self {
			detail = "uploaded certificate kept" // only other settings changed
			break
		}
		if _, err := ParseKeyPair(certPEM, keyPEM, c.Hostname, s.now()); err != nil {
			s.redirectErr(w, r, "/settings/certificate", err)
			return
		}
		if err := s.TLS.Install(certPEM, keyPEM); err != nil {
			s.serverError(w, r, err)
			return
		}
		i := s.TLS.Info()
		detail = "uploaded certificate for " + strings.Join(i.Names, ", ") + " (expires " + i.NotAfter.Format("2006-01-02") + ")"
	}
	if err := s.store.SetSetting(ctx, settingCert, c); err != nil {
		s.serverError(w, r, err)
		return
	}
	msg := "Saved."
	if err := s.applyPort80(ctx, c); err != nil {
		msg = s.errText(r, err)
	}
	if c.Mode == "acme" {
		c.CloudflareToken = s.certToken(c)
		if err := s.TLS.Obtain(ctx, c, s.httpClient()); err != nil {
			s.audit(r, "settings.certificate", "settings", "Let's Encrypt for %s failed: %v", c.Hostname, err)
			s.redirectErr(w, r, "/settings/certificate", err)
			return
		}
		i := s.TLS.Info()
		detail = "certificate from Let's Encrypt for " + c.Hostname + " (expires " + i.NotAfter.Format("2006-01-02") + ")"
		msg = "The certificate from Let's Encrypt is installed."
	}
	s.audit(r, "settings.certificate", "settings", "console certificate: %s; port 80: %v", detail, c.HTTP80)
	s.redirect(w, r, "/settings/certificate", msg)
}

func (s *Server) handleCertRenew(w http.ResponseWriter, r *http.Request) {
	c := s.Cert(r.Context())
	if c.Mode != "acme" {
		s.redirect(w, r, "/settings/certificate", "Only certificates from Let's Encrypt are renewed by the server.")
		return
	}
	c.CloudflareToken = s.certToken(c)
	if err := s.TLS.Obtain(r.Context(), c, s.httpClient()); err != nil {
		s.audit(r, "settings.certificate", "settings", "Let's Encrypt renewal for %s failed: %v", c.Hostname, err)
		s.redirectErr(w, r, "/settings/certificate", err)
		return
	}
	s.audit(r, "settings.certificate", "settings", "certificate for %s renewed by hand", c.Hostname)
	s.redirect(w, r, "/settings/certificate", "The certificate from Let's Encrypt is installed.")
}

// applyPort80 starts or stops the port 80 listener.
func (s *Server) applyPort80(_ context.Context, c CertSettings) error {
	if s.TLS == nil {
		return nil
	}
	s.TLS.Redirect = func(host string) string {
		_, port, _ := splitListen(s.RunningMgmt)
		if c.Hostname != "" && c.Mode != "self" {
			host = c.Hostname
		}
		if port == 443 {
			return "https://" + host + "/"
		}
		return "https://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/"
	}
	if err := s.TLS.ServeHTTP80(c.HTTP80, s.Port80Addr); err != nil {
		return uiErr("Saved, but port 80 cannot be used: " + err.Error())
	}
	return nil
}

func (s *Server) httpClient() *http.Client { return &http.Client{Timeout: 60 * time.Second} }

// RunCertificates starts port 80 and renews certificates from Let's Encrypt
// (checked twice a day, renewed 30 days before they expire).
func (s *Server) RunCertificates(ctx context.Context) {
	if s.TLS == nil {
		return
	}
	if err := s.applyPort80(ctx, s.Cert(ctx)); err != nil {
		s.log.Warn("port 80", "err", err)
	}
	t := time.NewTicker(12 * time.Hour)
	defer t.Stop()
	for {
		if c := s.Cert(ctx); c.Mode == "acme" && s.TLS.NeedsRenewal() {
			c.CloudflareToken = s.certToken(c)
			if err := s.TLS.Obtain(ctx, c, s.httpClient()); err != nil {
				s.log.Warn("certificate renewal failed", "host", c.Hostname, "err", err)
				_ = s.store.Audit(ctx, "-", "local", "settings.certificate", "settings", "automatic Let's Encrypt renewal for "+c.Hostname+" failed: "+err.Error())
			} else {
				_ = s.store.Audit(ctx, "-", "local", "settings.certificate", "settings", "certificate for "+c.Hostname+" renewed automatically")
			}
		}
		select {
		case <-ctx.Done():
			_ = s.TLS.ServeHTTP80(false, "")
			return
		case <-t.C:
		}
	}
}
