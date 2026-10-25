package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/crewjam/saml"
	"golang.org/x/oauth2"

	"github.com/max-zit/controlzit/internal/auth"
	"github.com/max-zit/controlzit/internal/store"
)

// Single sign-on (Settings → Single sign-on): OpenID Connect (Microsoft
// Entra ID, Google, Okta, Keycloak …) or SAML 2.0 (ADFS, Entra ID, Okta …).
// Users are created at their first sign-in; their role and customers follow
// their groups at every sign-in. Local accounts keep working, so an
// administrator can always sign in.

const settingSSO = "sso"

// SSOSettings configure single sign-on.
type SSOSettings struct {
	Protocol string `json:"protocol"` // "", oidc, saml
	Label    string `json:"label,omitempty"`
	// OpenID Connect.
	Issuer       string `json:"issuer,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"` // sealed
	// SAML: the identity provider's metadata, by URL or pasted.
	MetadataURL string `json:"metadata_url,omitempty"`
	MetadataXML string `json:"metadata_xml,omitempty"`
	// CACert (PEM) trusts an identity provider with a company CA.
	CACert string `json:"ca_cert,omitempty"`
	// The console's SAML signing key (sealed) and certificate.
	SPKey  string `json:"sp_key,omitempty"`
	SPCert string `json:"sp_cert,omitempty"`
	// Claims or attributes with the user name and the groups.
	UsernameClaim string `json:"username_claim,omitempty"`
	GroupsClaim   string `json:"groups_claim,omitempty"`
	// RequireTOTP also asks for ControlZit's own second factor.
	RequireTOTP bool         `json:"require_totp,omitempty"`
	Groups      GroupMapping `json:"groups"`
}

func (c SSOSettings) label() string {
	if c.Label != "" {
		return c.Label
	}
	return "Single sign-on"
}

// Validate checks the settings.
func (c *SSOSettings) Validate() error {
	if c.CACert != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CACert)) {
		return uiErr("The CA certificate must be in PEM format (-----BEGIN CERTIFICATE-----).")
	}
	switch c.Protocol {
	case "":
		return nil
	case "oidc":
		u, err := url.Parse(c.Issuer)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return uiErr("The issuer must be an https:// address, e.g. https://login.microsoftonline.com/<tenant>/v2.0.")
		}
		if c.ClientID == "" || c.ClientSecret == "" {
			return uiErr("Enter the client ID and the client secret of the application registered at the identity provider.")
		}
	case "saml":
		if c.MetadataURL == "" && c.MetadataXML == "" {
			return uiErr("Enter the identity provider's metadata URL or paste its metadata XML.")
		}
		if c.MetadataURL != "" {
			if u, err := url.Parse(c.MetadataURL); err != nil || u.Scheme != "https" || u.Host == "" {
				return uiErr("The metadata URL must be an https:// address.")
			}
		}
	default:
		return uiErr("Unknown single sign-on protocol.")
	}
	return c.Groups.validate()
}

// SSO loads the settings (secrets sealed).
func (s *Server) SSO(ctx context.Context) SSOSettings {
	var c SSOSettings
	c.Groups.AllByDefault = true
	_ = s.store.GetSetting(ctx, settingSSO, &c)
	return c
}

func (s *Server) ssoSecret(sealed, purpose string) string {
	if sealed == "" {
		return ""
	}
	v, _ := s.store.OpenSecret(purpose, sealed)
	return v
}

// baseURL is the console's address as the browser uses it; the identity
// provider must know the addresses below it.
func baseURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http" // only the loopback development listener
	}
	return scheme + "://" + r.Host
}

// ---- signed state (a cookie the callback must find again)

const ssoCookie = "czsso"

// ssoKey signs the state cookie; per process (a sign-in takes minutes).
var ssoKey = func() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}()

func signState(values ...string) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(strings.Join(append(values, fmt.Sprint(time.Now().Add(10*time.Minute).Unix())), "\x00")))
	m := hmac.New(sha256.New, ssoKey)
	m.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func parseState(tok string) ([]string, bool) {
	payload, sig, ok := strings.Cut(tok, ".")
	if !ok {
		return nil, false
	}
	m := hmac.New(sha256.New, ssoKey)
	m.Write([]byte(payload))
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, m.Sum(nil)) {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, false
	}
	v := strings.Split(string(b), "\x00")
	if len(v) < 2 {
		return nil, false
	}
	var exp int64
	if _, err := fmt.Sscan(v[len(v)-1], &exp); err != nil || time.Now().Unix() > exp {
		return nil, false
	}
	return v[:len(v)-1], true
}

// The SAML response is a cross-site POST, so the cookie is SameSite=None
// (it holds only the signed state, nothing that grants access).
func setSSOCookie(w http.ResponseWriter, r *http.Request, v string, maxAge int) {
	// #nosec G124 -- Secure whenever the request came over TLS (only the loopback dev listener is plain)
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: v, Path: "/login/sso", MaxAge: maxAge, HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteNoneMode})
}

// ---- providers (cached per configuration)

type ssoCache struct {
	mu   sync.Mutex
	key  string
	at   time.Time
	oidc *oidc.Provider
	idp  *saml.EntityDescriptor
}

func (c SSOSettings) cacheKey() string {
	return c.Protocol + "|" + c.Issuer + "|" + c.MetadataURL + "|" + fmt.Sprint(len(c.MetadataXML)) + "|" + c.CACert
}

func (c SSOSettings) client() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CACert != "" {
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		pool.AppendCertsFromPEM([]byte(c.CACert))
		tr.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: tr}
}

func (s *Server) oidcFor(ctx context.Context, c SSOSettings, r *http.Request) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	s.sso.mu.Lock()
	defer s.sso.mu.Unlock()
	if s.sso.key != c.cacheKey() || s.sso.oidc == nil || time.Since(s.sso.at) > time.Hour {
		p, err := oidc.NewProvider(oidc.ClientContext(ctx, c.client()), c.Issuer)
		if err != nil {
			return nil, nil, uiErrf("The identity provider cannot be reached: %v", err)
		}
		s.sso.key, s.sso.at, s.sso.oidc = c.cacheKey(), time.Now(), p
	}
	cfg := &oauth2.Config{ClientID: c.ClientID, ClientSecret: s.ssoSecret(c.ClientSecret, "settings.sso.client"), Endpoint: s.sso.oidc.Endpoint(),
		RedirectURL: baseURL(r) + "/login/sso/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}
	return cfg, s.sso.oidc.Verifier(&oidc.Config{ClientID: c.ClientID}), nil
}

// serviceProvider is the console as a SAML service provider.
func (s *Server) serviceProvider(ctx context.Context, c SSOSettings, r *http.Request) (*saml.ServiceProvider, error) {
	s.sso.mu.Lock()
	if s.sso.key != c.cacheKey() || s.sso.idp == nil || time.Since(s.sso.at) > time.Hour {
		var md *saml.EntityDescriptor
		var err error
		if c.MetadataXML != "" {
			md, err = parseIDPMetadata([]byte(c.MetadataXML))
		} else {
			md, err = fetchIDPMetadata(ctx, c.client(), c.MetadataURL)
		}
		if err != nil {
			s.sso.mu.Unlock()
			return nil, uiErrf("The metadata of the identity provider cannot be read: %v", err)
		}
		s.sso.key, s.sso.at, s.sso.idp = c.cacheKey(), time.Now(), md
	}
	idp := s.sso.idp
	s.sso.mu.Unlock()
	keyPEM := s.ssoSecret(c.SPKey, "settings.sso.spkey")
	blk, _ := pem.Decode([]byte(keyPEM))
	cblk, _ := pem.Decode([]byte(c.SPCert))
	if blk == nil || cblk == nil {
		return nil, errors.New("the console's SAML key is missing; save the settings again")
	}
	key, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, err
	}
	base := baseURL(r)
	md, _ := url.Parse(base + "/login/sso/metadata")
	acs, _ := url.Parse(base + "/login/sso/saml")
	return &saml.ServiceProvider{EntityID: md.String(), Key: key, Certificate: cert, MetadataURL: *md, AcsURL: *acs, IDPMetadata: idp,
		AuthnNameIDFormat: saml.UnspecifiedNameIDFormat, HTTPClient: c.client()}, nil
}

// newSPKey makes the console's SAML signing key and certificate.
func newSPKey() (keyPEM, certPEM string, err error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "ControlZit console (SAML)"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(20, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// ---- sign-in

func (s *Server) handleSSOStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c := s.SSO(ctx)
	next := safeNext(r.FormValue("next"))
	switch c.Protocol {
	case "oidc":
		cfg, _, err := s.oidcFor(ctx, c, r)
		if err != nil {
			s.ssoFailed(w, r, err)
			return
		}
		state, nonce, verifier := auth.RandomToken(16), auth.RandomToken(16), oauth2.GenerateVerifier()
		setSSOCookie(w, r, signState("oidc", state, nonce, verifier, next), 600)
		http.Redirect(w, r, cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusSeeOther)
	case "saml":
		sp, err := s.serviceProvider(ctx, c, r)
		if err != nil {
			s.ssoFailed(w, r, err)
			return
		}
		req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
		if err != nil {
			s.ssoFailed(w, r, err)
			return
		}
		relay := auth.RandomToken(12)
		u, err := req.Redirect(relay, sp)
		if err != nil {
			s.ssoFailed(w, r, err)
			return
		}
		setSSOCookie(w, r, signState("saml", req.ID, relay, next), 600)
		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c := s.SSO(ctx)
	ck, err := r.Cookie(ssoCookie)
	if err != nil || c.Protocol != "oidc" {
		s.ssoFailed(w, r, uiErr("The sign-in took too long or was started elsewhere. Try again."))
		return
	}
	v, ok := parseState(ck.Value)
	if !ok || len(v) != 5 || v[0] != "oidc" || r.FormValue("state") != v[1] {
		s.ssoFailed(w, r, uiErr("The sign-in took too long or was started elsewhere. Try again."))
		return
	}
	if e := r.FormValue("error"); e != "" {
		s.ssoFailed(w, r, uiErrf("The identity provider refused the sign-in: %s", clipText(e+" "+r.FormValue("error_description"), 200)))
		return
	}
	cfg, verifier, err := s.oidcFor(ctx, c, r)
	if err != nil {
		s.ssoFailed(w, r, err)
		return
	}
	tok, err := cfg.Exchange(oidc.ClientContext(ctx, c.client()), r.FormValue("code"), oauth2.VerifierOption(v[3]))
	if err != nil {
		s.ssoFailed(w, r, uiErrf("The identity provider did not confirm the sign-in: %v", err))
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := verifier.Verify(ctx, raw)
	if err != nil || idt.Nonce != v[2] {
		s.ssoFailed(w, r, uiErrf("The identity token is not valid: %v", err))
		return
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		s.ssoFailed(w, r, err)
		return
	}
	userClaim := orDefault(c.UsernameClaim, "preferred_username")
	name := claimString(claims, userClaim, "preferred_username", "upn", "email")
	groups := claimStrings(claims[orDefault(c.GroupsClaim, "groups")])
	s.ssoSignIn(w, r, c, name, claimString(claims, "name"), claimString(claims, "email"), groups, v[4])
}

func (s *Server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c := s.SSO(ctx)
	ck, err := r.Cookie(ssoCookie)
	if err != nil || c.Protocol != "saml" {
		s.ssoFailed(w, r, uiErr("The sign-in took too long or was started elsewhere. Try again."))
		return
	}
	v, ok := parseState(ck.Value)
	if !ok || len(v) != 4 || v[0] != "saml" {
		s.ssoFailed(w, r, uiErr("The sign-in took too long or was started elsewhere. Try again."))
		return
	}
	sp, err := s.serviceProvider(ctx, c, r)
	if err != nil {
		s.ssoFailed(w, r, err)
		return
	}
	if err := r.ParseForm(); err != nil || r.PostForm.Get("RelayState") != v[2] {
		s.ssoFailed(w, r, uiErr("The sign-in took too long or was started elsewhere. Try again."))
		return
	}
	// Signed by the identity provider and the answer to our own request.
	a, err := sp.ParseResponse(r, []string{v[1]})
	if err != nil {
		detail := err.Error()
		var ie *saml.InvalidResponseError
		if errors.As(err, &ie) {
			detail = ie.PrivateErr.Error()
		}
		s.log.Warn("SAML response refused", "err", detail)
		s.ssoFailed(w, r, uiErr("The response of the identity provider is not valid."))
		return
	}
	attrs := map[string][]string{}
	for _, st := range a.AttributeStatements {
		for _, at := range st.Attributes {
			for _, val := range at.Values {
				attrs[at.Name] = append(attrs[at.Name], val.Value)
				if at.FriendlyName != "" {
					attrs[at.FriendlyName] = append(attrs[at.FriendlyName], val.Value)
				}
			}
		}
	}
	first := func(keys ...string) string {
		for _, k := range keys {
			if vs := attrs[k]; len(vs) > 0 && vs[0] != "" {
				return vs[0]
			}
		}
		return ""
	}
	name := ""
	if c.UsernameClaim != "" {
		name = first(c.UsernameClaim)
	}
	if name == "" && a.Subject != nil && a.Subject.NameID != nil {
		name = a.Subject.NameID.Value
	}
	groups := attrs[orDefault(c.GroupsClaim, "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups")]
	if len(groups) == 0 {
		groups = append(attrs["groups"], attrs["Group"]...)
	}
	display := first("http://schemas.microsoft.com/identity/claims/displayname", "displayName", "name", "cn")
	email := first("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "email", "mail")
	s.ssoSignIn(w, r, c, name, display, email, groups, v[3])
}

// handleSAMLMetadata is the console's SAML metadata for the identity
// provider.
func (s *Server) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	c := s.SSO(r.Context())
	if c.Protocol != "saml" {
		http.NotFound(w, r)
		return
	}
	sp, err := s.serviceProvider(r.Context(), c, r)
	if err != nil {
		http.Error(w, s.errText(r, err), http.StatusServiceUnavailable)
		return
	}
	b, err := xmlMarshal(sp.Metadata())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(b)
}

// ssoSignIn creates or updates the user and starts the session.
func (s *Server) ssoSignIn(w http.ResponseWriter, r *http.Request, c SSOSettings, name, display, email string, groups []string, next string) {
	ctx := r.Context()
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		s.ssoFailed(w, r, uiErr("The identity provider sent no usable user name (check the user name claim)."))
		return
	}
	role, all, ids, err := s.resolve(ctx, c.Groups, groups)
	if err != nil {
		s.auditAs(r, clipText(name, 64), "login.failed", "user:"+clipText(name, 64), "single sign-on refused for groups %s: %v", clipText(strings.Join(groups, ", "), 300), err)
		s.ssoFailed(w, r, err)
		return
	}
	u, err := s.store.UpsertDirectoryUser(ctx, store.DirectoryUser{Source: "sso", Username: name, DisplayName: display, Email: email, Role: role, AllCustomers: all, CustomerIDs: ids})
	if errors.Is(err, store.ErrOtherSource) {
		s.auditAs(r, name, "login.failed", "user:"+name, "single sign-on for an account of another sign-in method")
		s.ssoFailed(w, r, uiErrf("The user %s exists in ControlZit with another sign-in method.", name))
		return
	}
	if err != nil {
		s.ssoFailed(w, r, err)
		return
	}
	if u.Disabled {
		s.ssoFailed(w, r, uiErr("This account is disabled."))
		return
	}
	setSSOCookie(w, r, "", -1)
	tok, x, err := s.store.CreateSession(ctx, u.ID, store.StageMFA, store.MFATimeout, clientIP(r), r.UserAgent())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if c.RequireTOTP && !s.DevNo2FA {
		s.setSessionCookie(w, r, tok, store.MFATimeout)
		to := "/login/2fa"
		if !u.TOTPEnabled {
			to = "/login/enroll"
		}
		http.Redirect(w, r, to+"?next="+url.QueryEscape(next), http.StatusSeeOther)
		return
	}
	if s.finishLogin(w, r, x, u, "single sign-on") {
		http.Redirect(w, r, next, http.StatusSeeOther)
	}
}

func (s *Server) ssoFailed(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Warn("single sign-on failed", "err", err, "ip", clientIP(r))
	p := &Page{Title: "Sign in", Data: &loginData{Next: "/"}}
	p.Error = translate(s.lang(r, nil), "Single sign-on failed:") + " " + s.errText(r, err)
	s.render(w, r, http.StatusUnauthorized, "login", p)
}

func orDefault(s, def string) string {
	if s != "" {
		return s
	}
	return def
}

func claimString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func claimStrings(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{x}
	}
	return nil
}

func clipText(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func xmlMarshal(v any) ([]byte, error) {
	b, err := xml.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), b...), nil
}

// parseIDPMetadata reads an EntityDescriptor, or the first one of an
// EntitiesDescriptor (federation metadata).
func parseIDPMetadata(b []byte) (*saml.EntityDescriptor, error) {
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(b, &ed); err == nil && len(ed.IDPSSODescriptors) > 0 {
		return &ed, nil
	}
	var eds saml.EntitiesDescriptor
	if err := xml.Unmarshal(b, &eds); err != nil {
		return nil, err
	}
	for i := range eds.EntityDescriptors {
		if len(eds.EntityDescriptors[i].IDPSSODescriptors) > 0 {
			return &eds.EntityDescriptors[i], nil
		}
	}
	return nil, errors.New("no identity provider in the metadata")
}

func fetchIDPMetadata(ctx context.Context, hc *http.Client, u string) (*saml.EntityDescriptor, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	return parseIDPMetadata(b)
}

// ---- Settings → Single sign-on

type ssoData struct {
	S         SSOSettings
	HasSecret bool
	Groups    string
	Base      string
}

func (s *Server) handleSSOSettings(w http.ResponseWriter, r *http.Request) {
	c := s.SSO(r.Context())
	d := &ssoData{S: c, HasSecret: c.ClientSecret != "", Groups: strings.Join(c.Groups.CustomerGroups, "\n"), Base: baseURL(r)}
	d.S.ClientSecret, d.S.SPKey = "", ""
	s.render(w, r, http.StatusOK, "sso", &Page{Title: "Single sign-on", Nav: "settings", Data: d})
}

func (s *Server) handleSSOSave(w http.ResponseWriter, r *http.Request) {
	old := s.SSO(r.Context())
	c := SSOSettings{Protocol: r.FormValue("protocol"), Label: strings.TrimSpace(r.FormValue("label")), Issuer: strings.TrimSpace(r.FormValue("issuer")),
		ClientID: strings.TrimSpace(r.FormValue("client_id")), ClientSecret: old.ClientSecret, MetadataURL: strings.TrimSpace(r.FormValue("metadata_url")),
		MetadataXML: strings.TrimSpace(r.FormValue("metadata_xml")), CACert: strings.TrimSpace(r.FormValue("ca_cert")), SPKey: old.SPKey, SPCert: old.SPCert,
		UsernameClaim: strings.TrimSpace(r.FormValue("username_claim")), GroupsClaim: strings.TrimSpace(r.FormValue("groups_claim")),
		RequireTOTP: r.FormValue("require_totp") == "1", Groups: mappingFromForm(r.FormValue)}
	if v := r.FormValue("client_secret"); v != "" {
		c.ClientSecret = s.store.SealSecret("settings.sso.client", v)
	}
	if err := c.Validate(); err != nil {
		s.redirectErr(w, r, "/settings/sso", err)
		return
	}
	if c.Protocol == "saml" && c.SPKey == "" {
		k, cert, err := newSPKey()
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		c.SPKey, c.SPCert = s.store.SealSecret("settings.sso.spkey", k), cert
	}
	if err := s.store.SetSetting(r.Context(), settingSSO, c); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.sso.mu.Lock()
	s.sso.key = "" // read the provider again
	s.sso.mu.Unlock()
	s.audit(r, "settings.sso", "settings", "single sign-on: %q %s%s, groups admin %q technician %q read-only %q default %q, own second factor %v",
		c.Protocol, c.Issuer, c.MetadataURL, c.Groups.AdminGroup, c.Groups.TechnicianGroup, c.Groups.ReadOnlyGroup, c.Groups.DefaultRole, c.RequireTOTP)
	s.redirect(w, r, "/settings/sso", "Saved.")
}
