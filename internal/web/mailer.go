package web

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/auth"
)

const settingEmail = "email"

// EmailSettings is the SMTP server for alert emails. The password is
// stored encrypted with the server's secret key.
type EmailSettings struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Security string `json:"security"` // starttls, tls, none
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"` // sealed in the database
	From     string `json:"from"`
}

// Configured reports whether email can be sent.
func (e *EmailSettings) Configured() bool { return e.Host != "" && e.From != "" }

// Validate checks the fields.
func (e *EmailSettings) Validate() error {
	if e.Host == "" {
		return nil // email off
	}
	if strings.ContainsAny(e.Host, " /\\") || len(e.Host) > 255 {
		return errors.New("the SMTP server must be a host name or an IP address")
	}
	if e.Port < 1 || e.Port > 65535 {
		return errors.New("the port must be 1–65535")
	}
	if e.Security != "starttls" && e.Security != "tls" && e.Security != "none" {
		return errors.New("unknown connection security")
	}
	if _, err := mail.ParseAddress(e.From); err != nil {
		return errors.New("the sender must be an email address")
	}
	if e.Username != "" && e.Security == "none" && !isLocalHost(e.Host) {
		return errors.New("a password is sent only over an encrypted connection (STARTTLS or TLS)")
	}
	return nil
}

func isLocalHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Email loads the SMTP settings with the password decrypted.
func (s *Server) Email(ctx context.Context) EmailSettings {
	var e EmailSettings
	if err := s.store.GetSetting(ctx, settingEmail, &e); err != nil {
		return EmailSettings{}
	}
	if e.Password != "" {
		p, err := s.store.OpenSecret("settings.email.password", e.Password)
		if err != nil {
			s.log.Error("cannot decrypt the SMTP password", "err", err)
			p = ""
		}
		e.Password = p
	}
	return e
}

// SaveEmail stores the settings; an empty password keeps the old one.
func (s *Server) SaveEmail(ctx context.Context, e EmailSettings) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if e.Password == "" {
		e.Password = s.Email(ctx).Password
	}
	if e.Password != "" {
		e.Password = s.store.SealSecret("settings.email.password", e.Password)
	}
	return s.store.SetSetting(ctx, settingEmail, e)
}

// headerSafe removes line breaks from header values.
func headerSafe(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }

// sendMail sends a plain-text message to the recipients.
func sendMail(ctx context.Context, e EmailSettings, to []string, subject, body string) error {
	return sendMailParts(ctx, e, to, subject, body, "")
}

// sendMailHTML sends a message with a text and an HTML version.
func sendMailHTML(ctx context.Context, e EmailSettings, to []string, subject, text, html string) error {
	return sendMailParts(ctx, e, to, subject, text, html)
}

func sendMailParts(ctx context.Context, e EmailSettings, to []string, subject, body, html string) error {
	if !e.Configured() {
		return errors.New("email is not set up")
	}
	if len(to) == 0 {
		return errors.New("no recipients")
	}
	addr := net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	d := net.Dialer{Timeout: 20 * time.Second}
	var conn net.Conn
	var err error
	tc := &tls.Config{ServerName: e.Host, MinVersion: tls.VersionTLS12}
	if e.Security == "tls" {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, tc)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("cannot reach the SMTP server: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	}
	c, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer c.Close()
	if e.Security == "starttls" {
		if err := c.StartTLS(tc); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}
	if e.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", e.Username, e.Password, e.Host)); err != nil {
			return fmt.Errorf("SMTP sign-in: %w", err)
		}
	}
	from, _ := mail.ParseAddress(e.From)
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	for _, r := range to {
		a, err := mail.ParseAddress(r)
		if err != nil {
			return err
		}
		if err := c.Rcpt(a.Address); err != nil {
			return fmt.Errorf("recipient %s: %w", a.Address, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("From: " + headerSafe(e.From) + "\r\n")
	b.WriteString("To: " + headerSafe(strings.Join(to, ", ")) + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", headerSafe(subject)) + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	text := strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")
	if html == "" {
		b.WriteString("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + text)
	} else {
		boundary := "cz-" + auth.RandomToken(12)
		b.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n")
		b.WriteString("--" + boundary + "\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + text + "\r\n")
		b.WriteString("--" + boundary + "\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n")
		enc := base64.StdEncoding.EncodeToString([]byte(html))
		for len(enc) > 76 {
			b.WriteString(enc[:76] + "\r\n")
			enc = enc[76:]
		}
		b.WriteString(enc + "\r\n--" + boundary + "--\r\n")
	}
	if _, err := w.Write([]byte(b.String())); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
