// Package web is the management console (HTML + later JSON API) and the
// agent endpoint of the ControlZit server. They are served on separate
// listeners: the agent endpoint may be public, the console is reachable
// only from the allowed networks.
package web

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/netacl"
	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

// Server serves the console and the agent endpoint.
type Server struct {
	store *store.Store
	pkg   packageCache
	jobs  jobRunner
	tasks taskRunner
	log   *slog.Logger
	tmpl  map[string]*template.Template
	now   func() time.Time
	guard *loginGuard
	hub   *hub
	rd    rdHub

	// TaskWait is how long a page waits for a new task (0: taskWait).
	TaskWait time.Duration

	// MgmtACL guards the console listener, AgentACL the agent listener.
	MgmtACL  *netacl.List
	AgentACL *netacl.List

	// Running are the listen addresses the server actually uses (they
	// can differ from the saved settings until a restart).
	RunningMgmt, RunningAgent string
	// ListenOverride: the addresses come from command-line options, not
	// from the saved settings.
	ListenOverride bool
	// AgentFingerprint is the SHA-256 of the agent certificate.
	AgentFingerprint string
	Version          string

	// SetupTokenFile holds the one-time token the first-run setup asks for.
	SetupTokenFile string
	// DevNo2FA skips the second factor (development server only; the
	// command refuses it without the embedded development database).
	DevNo2FA bool
	// DownloadsDir holds the agent installer offered in the console.
	DownloadsDir string
	// CommandKey signs every command to agents.
	CommandKey ed25519.PrivateKey
	// TLS serves the console certificate (Settings → Certificate) and port 80.
	TLS *ConsoleTLS
	// Port80Addr is where port 80 listens when it is switched on (":80").
	Port80Addr string
	// DataDir is the data directory (the root helper reads requests from it).
	DataDir string
	// LogFile is the server's log file (Settings → Diagnostics).
	LogFile string
	// HelperAvailable overrides the check for the root helper (tests).
	HelperAvailable func() bool
	upd             updateState
	sso             ssoCache
	setupToken      string
}

// New creates the server; network settings are loaded from the database.
func New(ctx context.Context, st *store.Store, log *slog.Logger) (*Server, error) {
	t, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	s := &Server{store: st, log: log, tmpl: t, now: time.Now, Version: "dev", hub: newHub()}
	if err := st.ResetConnected(ctx); err != nil {
		return nil, err
	}
	// Job runs in flight when the server stopped cannot report any more.
	if err := st.ExpireJobs(ctx, true); err != nil {
		return nil, err
	}
	if err := st.ExpireTasks(ctx, true); err != nil {
		return nil, err
	}
	s.guard = newLoginGuard(st, func() time.Time { return s.now() })
	n, err := s.Network(ctx)
	if err != nil {
		return nil, err
	}
	mg, _ := netacl.Parse(n.MgmtAllowed)
	ag, _ := netacl.Parse(n.AgentAllowed)
	s.MgmtACL = netacl.NewManagement(mg)
	s.AgentACL = netacl.NewOptional(ag)
	return s, nil
}

// SetClock replaces the clock (tests).
func (s *Server) SetClock(now func() time.Time) { s.now = now }

// SetSetupToken sets the token the first-run setup requires.
func (s *Server) SetSetupToken(tok string) { s.setupToken = tok }

// ---- network settings

const settingNetwork = "network"

// NetworkSettings are the two listeners and who may reach them.
type NetworkSettings struct {
	// MgmtListen is the console address, e.g. ":8443" or "192.168.1.10:8443".
	MgmtListen string `json:"mgmt_listen"`
	// AgentListen is the agent endpoint, e.g. ":8444". It must be a
	// different port so a firewall can treat the two separately.
	AgentListen string `json:"agent_listen"`
	// MgmtAllowed may reach the console (loopback always may).
	MgmtAllowed []string `json:"mgmt_allowed"`
	// AgentAllowed may reach the agent endpoint; empty = everyone.
	AgentAllowed []string `json:"agent_allowed"`
	// PublicAgentURL is how agents reach the server (put into installers),
	// e.g. "https://rmm.example.com:8444". Empty: derived from the console address.
	PublicAgentURL string `json:"public_agent_url,omitempty"`
}

// defaultNetwork is used until the settings are saved (a fresh copy each
// time: JSON decoding into it must not change the package defaults).
func defaultNetwork() NetworkSettings {
	return NetworkSettings{MgmtListen: ":8443", AgentListen: ":8444", MgmtAllowed: append([]string(nil), netacl.DefaultManagement...)}
}

// Validate checks the listen addresses and the networks.
func (n *NetworkSettings) Validate() error {
	mh, mp, err := splitListen(n.MgmtListen)
	if err != nil {
		return fmt.Errorf("console address: %w", err)
	}
	ah, ap, err := splitListen(n.AgentListen)
	if err != nil {
		return fmt.Errorf("agent address: %w", err)
	}
	if mp == ap && (mh == ah || mh == "" || ah == "") {
		return errors.New("the console and the agent endpoint must use different ports")
	}
	if _, err := netacl.Parse(n.MgmtAllowed); err != nil {
		return err
	}
	if _, err := netacl.Parse(n.AgentAllowed); err != nil {
		return err
	}
	if n.PublicAgentURL != "" {
		u, err := url.Parse(n.PublicAgentURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.User != nil {
			return errors.New("the public agent address must look like https://rmm.example.com:8444")
		}
	}
	return nil
}

func splitListen(a string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(strings.TrimSpace(a))
	if err != nil {
		return "", 0, errors.New("use host:port or :port, e.g. :8443")
	}
	port, err = strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("the port must be 1–65535")
	}
	if h != "" {
		if _, err := netip.ParseAddr(h); err != nil {
			return "", 0, errors.New("the host must be an IP address of this server (or empty for all)")
		}
	}
	return h, port, nil
}

// Network loads the network settings.
func (s *Server) Network(ctx context.Context) (NetworkSettings, error) {
	n := defaultNetwork()
	if err := s.store.GetSetting(ctx, settingNetwork, &n); err != nil {
		return n, err
	}
	if n.Validate() != nil {
		s.log.Warn("invalid network settings in the database; using defaults")
		n = defaultNetwork()
	}
	return n, nil
}

// SaveNetwork stores the settings and applies the allow-lists at once.
func (s *Server) SaveNetwork(ctx context.Context, n NetworkSettings) error {
	if err := n.Validate(); err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingNetwork, n); err != nil {
		return err
	}
	mg, _ := netacl.Parse(n.MgmtAllowed)
	ag, _ := netacl.Parse(n.AgentAllowed)
	s.MgmtACL.Set(mg)
	s.AgentACL.SetOptional(ag)
	return nil
}

// ResetMgmtAllowList restores the default console networks (CLI, for an
// administrator who locked themselves out).
func ResetMgmtAllowList(ctx context.Context, st *store.Store) error {
	n := defaultNetwork()
	if err := st.GetSetting(ctx, settingNetwork, &n); err != nil {
		return err
	}
	n.MgmtAllowed = append([]string(nil), netacl.DefaultManagement...)
	if n.Validate() != nil {
		n = defaultNetwork()
	}
	return st.SetSetting(ctx, settingNetwork, n)
}

// ---- security settings

const settingSecurity = "security"

// SecuritySettings control sessions and the brute-force protection.
type SecuritySettings struct {
	SessionHours int `json:"session_hours"`
	IdleMinutes  int `json:"idle_minutes"`
	// MaxAttempts failed sign-ins of one address within WindowMinutes
	// block it for BlockMinutes (doubling for repeated blocks in a day).
	MaxAttempts   int `json:"max_attempts"`
	WindowMinutes int `json:"window_minutes"`
	BlockMinutes  int `json:"block_minutes"`
}

// DefaultSecurity: short sessions, as the console controls every machine.
var DefaultSecurity = SecuritySettings{SessionHours: 8, IdleMinutes: 30, MaxAttempts: 5, WindowMinutes: 15, BlockMinutes: 30}

// Validate checks the ranges.
func (x SecuritySettings) Validate() error {
	switch {
	case x.SessionHours < 1 || x.SessionHours > 24:
		return errors.New("the session length must be 1–24 hours")
	case x.IdleMinutes < 5 || x.IdleMinutes > 480:
		return errors.New("the inactivity timeout must be 5–480 minutes")
	case x.MaxAttempts < 3 || x.MaxAttempts > 50:
		return errors.New("failed attempts must be 3–50")
	case x.WindowMinutes < 1 || x.WindowMinutes > 1440:
		return errors.New("the counting period must be 1–1440 minutes")
	case x.BlockMinutes < 1 || x.BlockMinutes > 10080:
		return errors.New("the block must last 1–10080 minutes")
	}
	return nil
}

func (s *Server) security(ctx context.Context) SecuritySettings {
	x := DefaultSecurity
	if err := s.store.GetSetting(ctx, settingSecurity, &x); err != nil || x.Validate() != nil {
		return DefaultSecurity
	}
	return x
}

// ---- handlers

// Handler is the management console. devHTTP marks the plain-HTTP
// development listener (cookies without Secure).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServer(http.FS(sub)))))
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/favicon.svg", http.StatusMovedPermanently)
	})

	mux.HandleFunc("GET /setup", s.handleSetup)
	mux.HandleFunc("POST /setup", s.handleSetup)
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("GET /login/2fa", s.handleLogin2FA)
	mux.HandleFunc("POST /login/2fa", s.handleLogin2FA)
	mux.HandleFunc("GET /login/enroll", s.handleEnroll)
	mux.HandleFunc("POST /login/enroll", s.handleEnroll)
	mux.HandleFunc("GET /login/sso", s.handleSSOStart)
	mux.HandleFunc("GET /login/sso/callback", s.handleOIDCCallback)
	mux.HandleFunc("POST /login/sso/saml", s.handleSAMLACS)
	mux.HandleFunc("GET /login/sso/metadata", s.handleSAMLMetadata)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("POST /lang", s.handleLang)

	app := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireUser(h)) }
	admin := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireUser(s.requireAdmin(h))) }
	app("GET /{$}", s.handleOverview)
	app("GET /customers", s.handleCustomers)
	app("POST /customers", s.handleCustomerCreate)
	app("GET /customers/{id}", s.handleCustomer)
	app("POST /customers/{id}", s.handleCustomerUpdate)
	app("POST /customers/{id}/delete", s.handleCustomerDelete)
	app("POST /customers/{id}/sites", s.handleSiteCreate)
	app("GET /sites/{id}", s.handleSite)
	app("POST /sites/{id}", s.handleSiteUpdate)
	app("POST /sites/{id}/delete", s.handleSiteDelete)
	app("POST /sites/{id}/tokens", s.handleTokenCreate)
	app("POST /sites/{id}/tokens/{tid}/revoke", s.handleTokenRevoke)
	app("GET /downloads/"+AgentMSIName, s.handleAgentMSI)
	app("GET /downloads/"+AgentLinuxName, s.agentLinux(AgentLinuxName))
	app("GET /downloads/"+AgentLinuxARM64Name, s.agentLinux(AgentLinuxARM64Name))
	app("GET /alerts", s.handleAlerts)
	app("POST /alerts/{id}/ack", s.handleAlertAck)
	app("GET /devices", s.handleDevices)
	app("GET /devices/{id}", s.handleDevice)
	app("GET /devices/{id}/rd", s.handleRD)
	app("GET /devices/{id}/rd/ws", s.handleRDSocket)
	app("POST /devices/{id}/rd/upload", s.handleRDUpload)
	app("GET /devices/{id}/terminal", s.handleTerm)
	app("GET /devices/{id}/terminal/ws", s.handleTermSocket)
	app("GET /devices/{id}/files", s.handleFiles)
	app("GET /devices/{id}/files/download", s.handleFileDownload)
	app("GET /devices/{id}/files/zip", s.handleFolderZip)
	app("POST /devices/{id}/files/upload", s.handleFileUpload)
	app("POST /devices/{id}/files/mkdir", s.handleFileMkdir)
	app("POST /devices/{id}/files/rename", s.handleFileRename)
	app("POST /devices/{id}/files/delete", s.handleFileDelete)
	app("GET /devices/{id}/services", s.handleServices)
	app("POST /devices/{id}/services", s.handleServiceControl)
	app("GET /devices/{id}/processes", s.handleProcesses)
	app("POST /devices/{id}/processes/kill", s.handleProcessKill)
	app("GET /devices/{id}/activity", s.handleActivity)
	app("POST /devices/{id}/activity/{tid}/cancel", s.handleTaskCancel)
	app("POST /devices/{id}/activity/jobs/{jid}/cancel", s.handleJobRunCancel)
	app("GET /devices/{id}/scripts", s.handleScripts)
	app("GET /devices/{id}/scripts/{rid}", s.handleScripts)
	app("POST /devices/{id}/scripts", s.handleScriptRun)
	app("POST /devices/{id}/power", s.handlePower)
	app("POST /devices/{id}/agent-update", s.handleDeviceUpdate)
	app("GET /devices/{id}/updates", s.handleDevicePatches)
	app("GET /devices/{id}/events", s.handleEvents)
	app("GET /devices/{id}/software", s.handleSoftware)
	app("POST /devices/{id}/software", s.handleSoftwareAction)
	app("POST /devices/{id}/updates/scan", s.handlePatchScan)
	app("POST /devices/{id}/updates/install", s.handlePatchInstall)
	app("GET /updates", s.handlePatchOverview)
	app("GET /reports", s.handleReports)
	app("GET /reports/view", s.handleReportView)
	app("GET /scripts", s.handleLibrary)
	app("GET /scripts/{sid}", s.handleLibScript)
	app("GET /scripts/{sid}/run", s.handleJobNew)
	app("POST /scripts/{sid}/run", s.handleJobCreate)
	app("GET /jobs/{jid}", s.handleJob)
	admin("GET /policies", s.handlePolicies)
	admin("GET /policies/new", s.handlePolicy)
	admin("POST /policies/new", s.handlePolicySave)
	admin("GET /policies/{pid}", s.handlePolicy)
	admin("POST /policies/{pid}", s.handlePolicySave)
	admin("POST /policies/{pid}/delete", s.handlePolicyDelete)
	admin("POST /policies/{pid}/assign", s.handlePolicyAssign)
	admin("POST /policies/{pid}/unassign", s.handlePolicyUnassign)
	app("GET /devices/{id}/policy", s.handleDevicePolicy)
	app("GET /devices/{id}/bitlocker", s.handleBitLocker)
	app("POST /devices/{id}/bitlocker/collect", s.handleBitLockerCollect)
	admin("POST /devices/{id}/bitlocker/enable", s.handleBitLockerEnable)
	admin("POST /devices/{id}/bitlocker/reveal", s.handleBitLockerReveal)
	admin("POST /devices/{id}/policy", s.handleDevicePolicyAssign)
	app("GET /software", s.handleSwLibrary)
	app("GET /software/{pid}", s.handleSwPackage)
	app("GET /software/{pid}/run", s.handleSwRunNew)
	app("POST /software/{pid}/run", s.handleSwRun)
	admin("GET /software/new", s.handleSwPackage)
	admin("POST /software/new", s.handleSwUpload)
	admin("POST /software/settings", s.handleSwSettings)
	admin("POST /software/{pid}", s.handleSwPackageSave)
	admin("POST /software/{pid}/delete", s.handleSwPackageDelete)
	admin("GET /scripts/new", s.handleLibScript)
	admin("POST /scripts/new", s.handleLibScriptSave)
	admin("POST /scripts/{sid}", s.handleLibScriptSave)
	admin("POST /scripts/{sid}/delete", s.handleLibScriptDelete)
	admin("POST /scripts/{sid}/schedules", s.handleScheduleAdd)
	admin("POST /schedules/{id}", s.handleScheduleChange)
	app("POST /devices/{id}/refresh", s.handleDeviceRefresh)
	app("POST /devices/{id}/delete", s.handleDeviceDelete)
	app("GET /account", s.handleAccount)
	app("POST /account/password", s.handleAccountPassword)
	app("POST /account/recovery", s.handleAccountRecovery)
	app("POST /account/sessions/signout", s.handleAccountSignout)
	app("POST /account/tokens", s.handleAPITokenCreate)
	app("POST /account/tokens/{tid}/delete", s.handleAPITokenDelete)
	admin("GET /users", s.handleUsers)
	admin("POST /users", s.handleUserCreate)
	admin("GET /users/{id}", s.handleUser)
	admin("POST /users/{id}", s.handleUserUpdate)
	admin("POST /users/{id}/password", s.handleUserPassword)
	admin("POST /users/{id}/reset-2fa", s.handleUserReset2FA)
	app("GET /docs", s.handleDocs)
	app("GET /docs/search", s.handleDocsSearch)
	app("GET /docs/{page}", s.handleDocs)
	admin("GET /audit", s.handleAudit)
	admin("GET /settings", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/settings/network", http.StatusFound)
	})
	admin("GET /settings/network", s.handleNetwork)
	admin("POST /settings/network", s.handleNetworkSave)
	admin("GET /settings/monitoring", s.handleMonitoringSettings)
	admin("GET /settings/remote", s.handleRemoteSettings)
	admin("POST /settings/remote", s.handleRemoteSave)
	admin("GET /settings/certificate", s.handleCertSettings)
	admin("POST /settings/certificate", s.handleCertSave)
	admin("POST /settings/certificate/renew", s.handleCertRenew)
	admin("POST /settings/timezone", s.handleTimeZone)
	admin("POST /settings/restart", s.handleRestart)
	admin("POST /settings/server-network", s.handleServerNetwork)
	admin("GET /settings/version", s.handleVersion)
	admin("POST /settings/version/check", s.handleVersionCheck)
	admin("POST /settings/version/install", s.handleVersionInstall)
	admin("POST /settings/version/settings", s.handleVersionSettings)
	admin("GET /settings/ldap", s.handleLDAPSettings)
	admin("POST /settings/ldap", s.handleLDAPSave)
	admin("POST /settings/ldap/test", s.handleLDAPTest)
	admin("GET /settings/sso", s.handleSSOSettings)
	admin("POST /settings/sso", s.handleSSOSave)
	admin("GET /settings/diagnostics", s.handleDiagnostics)
	admin("GET /settings/diagnostics/zip", s.handleDiagnosticsZip)
	admin("POST /settings/monitoring", s.handleMonitoringSave)
	admin("POST /settings/email", s.handleEmailSave)
	admin("POST /settings/email/test", s.handleEmailTest)
	admin("POST /settings/channels", s.handleChannels)
	admin("GET /settings/security", s.handleSecurity)
	admin("POST /settings/security", s.handleSecuritySave)
	admin("POST /settings/security/unblock", s.handleUnblock)
	admin("GET /settings/updates", s.handlePatchPolicy)
	admin("POST /settings/updates", s.handlePatchPolicySave)
	admin("GET /settings/reports", s.handleReportSettings)
	admin("POST /settings/reports", s.handleReportSettingsSave)
	admin("POST /settings/reports/send", s.handleReportSend)
	admin("GET /settings/agents", s.handleAgentUpdates)
	admin("POST /settings/agents", s.handleAgentUpdatesSave)
	admin("POST /settings/agents/package", s.handlePackageUpload)
	admin("POST /settings/agents/update-all", s.handleUpdateAll)

	// /api/ takes only API tokens (no session cookies), so it needs no CSRF check.
	api := s.APIHandler()
	console := s.csrf(s.loadSession(mux))
	return s.secure(s.aclCheck(s.MgmtACL, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			api.ServeHTTP(w, r)
			return
		}
		console.ServeHTTP(w, r)
	})))
}

// AgentHandler is the agent endpoint: enrollment, the agent channel and a
// health check. Agents authenticate with their TLS client certificate.
func (s *Server) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+proto.PathEnroll, s.handleAgentEnroll)
	mux.HandleFunc("GET "+proto.PathConnect, s.handleConnect)
	mux.HandleFunc("GET "+proto.PathStream, s.handleStream)
	mux.HandleFunc("GET "+proto.PathPackage, s.handlePackage)
	mux.HandleFunc("GET "+proto.PathLibrary, s.handleLibraryFile)
	mux.HandleFunc("GET "+proto.PathHealth, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","product":"controlzit"}`))
	})
	return agentHeaders(s.aclCheck(s.AgentACL, mux))
}

func agentHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		next.ServeHTTP(w, r)
	})
}

// secure sets the security headers of every console response.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// same-origin (not no-referrer): browsers then still send a real
		// Origin header on form posts, which the CSRF check needs.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// aclCheck repeats the listener's address check per request (defense in
// depth, and the dev HTTP listener has no listener check).
func (s *Server) aclCheck(l *netacl.List, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.AllowsAddr(r.RemoteAddr) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrf refuses state-changing requests that do not come from a page of
// this console: the Origin (or, without it, the Referer) must match the
// Host, and Sec-Fetch-Site, where sent, must be same-origin.
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		// The identity provider posts the SAML response from its own site; the
		// response is signed and must answer a request of this console.
		if r.Method == http.MethodPost && r.URL.Path == "/login/sso/saml" {
			next.ServeHTTP(w, r)
			return
		}
		if !sameOrigin(r) {
			s.log.Warn("cross-site request refused", "ip", clientIP(r), "path", r.URL.Path, "origin", r.Header.Get("Origin"))
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(r *http.Request) bool {
	if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	want := scheme + "://" + r.Host
	if o := r.Header.Get("Origin"); o != "" {
		return o == want
	}
	ref := r.Header.Get("Referer")
	return ref != "" && (ref == want || strings.HasPrefix(ref, want+"/"))
}

// clientIP is the address of the direct peer (no proxy support yet).
func clientIP(r *http.Request) string {
	if a, ok := netacl.AddrOf(r.RemoteAddr); ok {
		return a.String()
	}
	return r.RemoteAddr
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request failed", "path", r.URL.Path, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusNotFound, "notfound", &Page{Title: "Not found"})
}

func (s *Server) forbidden(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusForbidden, "forbidden", &Page{Title: "Not allowed"})
}

func pathID(r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	return id, err == nil && id > 0
}

// audit records an action of the signed-in user.
func (s *Server) audit(r *http.Request, action, target, format string, args ...any) {
	name := "-"
	if u := userFrom(r); u != nil {
		name = u.Username
	}
	s.auditAs(r, name, action, target, format, args...)
}

func (s *Server) auditAs(r *http.Request, user, action, target, format string, args ...any) {
	detail := format
	if len(args) > 0 {
		detail = fmt.Sprintf(format, args...)
	}
	if err := s.store.Audit(r.Context(), user, clientIP(r), action, target, detail); err != nil {
		s.log.Error("audit log write failed", "action", action, "err", err)
	}
}
