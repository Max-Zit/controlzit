package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/max-zit/controlzit/internal/netacl"
	"github.com/max-zit/controlzit/internal/store"
)

type networkData struct {
	N            NetworkSettings
	MgmtText     string
	AgentText    string
	RunningMgmt  string
	RunningAgent string
	Restart      bool
	Override     bool
	ClientIP     string
	Fingerprint  string
}

func (s *Server) handleNetwork(w http.ResponseWriter, r *http.Request) {
	n, err := s.Network(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.showNetwork(w, r, http.StatusOK, n, "")
}

func (s *Server) showNetwork(w http.ResponseWriter, r *http.Request, status int, n NetworkSettings, errMsg string) {
	d := &networkData{N: n, MgmtText: strings.Join(n.MgmtAllowed, "\n"), AgentText: strings.Join(n.AgentAllowed, "\n"),
		RunningMgmt: s.RunningMgmt, RunningAgent: s.RunningAgent, ClientIP: clientIP(r), Fingerprint: s.AgentFingerprint}
	d.Override = s.ListenOverride
	d.Restart = s.RunningMgmt != "" && !s.ListenOverride && (n.MgmtListen != s.RunningMgmt || n.AgentListen != s.RunningAgent)
	p := &Page{Title: "Network and access", Nav: "settings", Data: d}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "network", p)
}

func (s *Server) handleNetworkSave(w http.ResponseWriter, r *http.Request) {
	n := NetworkSettings{
		MgmtListen: strings.TrimSpace(r.FormValue("mgmt_listen")), AgentListen: strings.TrimSpace(r.FormValue("agent_listen")),
		MgmtAllowed: netacl.Split(r.FormValue("mgmt_allowed")), AgentAllowed: netacl.Split(r.FormValue("agent_allowed")),
		PublicAgentURL: strings.TrimRight(strings.TrimSpace(r.FormValue("public_agent_url")), "/"),
	}
	if err := n.Validate(); err != nil {
		s.showNetwork(w, r, http.StatusBadRequest, n, err.Error())
		return
	}
	// Normalize, and refuse a list that would lock out the administrator
	// who is saving it (loopback always works anyway).
	mg, _ := netacl.Parse(n.MgmtAllowed)
	ag, _ := netacl.Parse(n.AgentAllowed)
	n.MgmtAllowed, n.AgentAllowed = netacl.Strings(mg), netacl.Strings(ag)
	if a, ok := netacl.AddrOf(r.RemoteAddr); ok && !a.IsLoopback() && !netacl.Contains(mg, a) {
		s.showNetwork(w, r, http.StatusBadRequest, n, translate(s.lang(r, userFrom(r)),
			"Your address %s is not in the list of networks allowed to reach the console; saving it would lock you out. Add it first.", a.String()))
		return
	}
	old, _ := s.Network(r.Context())
	if err := s.SaveNetwork(r.Context(), n); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.network", "settings", "console %s allowed %v; agents %s allowed %v; public agent URL %q (was: console %s allowed %v; agents %s allowed %v)",
		n.MgmtListen, n.MgmtAllowed, n.AgentListen, n.AgentAllowed, n.PublicAgentURL, old.MgmtListen, old.MgmtAllowed, old.AgentListen, old.AgentAllowed)
	msg := "Saved. The allowed networks apply immediately."
	if s.RunningMgmt != "" && !s.ListenOverride && (n.MgmtListen != s.RunningMgmt || n.AgentListen != s.RunningAgent) {
		msg = "Saved. The allowed networks apply immediately; restart the ControlZit service to use the new ports."
	}
	s.redirect(w, r, "/settings/network", msg)
}

type securityData struct {
	X      SecuritySettings
	Blocks []store.Block
}

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	s.showSecurity(w, r, http.StatusOK, s.security(r.Context()), "")
}

func (s *Server) showSecurity(w http.ResponseWriter, r *http.Request, status int, x SecuritySettings, errMsg string) {
	blocks, err := s.store.Blocks(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	p := &Page{Title: "Sign-in and security", Nav: "settings", Data: &securityData{X: x, Blocks: blocks}}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "security", p)
}

func (s *Server) handleSecuritySave(w http.ResponseWriter, r *http.Request) {
	num := func(k string) int { n, _ := strconv.Atoi(strings.TrimSpace(r.FormValue(k))); return n }
	x := SecuritySettings{SessionHours: num("session_hours"), IdleMinutes: num("idle_minutes"), MaxAttempts: num("max_attempts"),
		WindowMinutes: num("window_minutes"), BlockMinutes: num("block_minutes")}
	if err := x.Validate(); err != nil {
		s.showSecurity(w, r, http.StatusBadRequest, x, err.Error())
		return
	}
	if err := s.store.SetSetting(r.Context(), settingSecurity, x); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.security", "settings", "sessions %dh, idle %dmin; block after %d failures in %dmin for %dmin",
		x.SessionHours, x.IdleMinutes, x.MaxAttempts, x.WindowMinutes, x.BlockMinutes)
	s.redirect(w, r, "/settings/security", "Saved.")
}

func (s *Server) handleUnblock(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.FormValue("ip"))
	if _, ok := netacl.AddrOf(ip); !ok && ip != "all" {
		s.showSecurity(w, r, http.StatusBadRequest, s.security(r.Context()), "Not an IP address.")
		return
	}
	if _, err := s.store.Unblock(r.Context(), ip); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "login.unblock", "ip:"+ip, "sign-in block lifted")
	s.redirect(w, r, "/settings/security", "Block lifted.")
}

type auditData struct {
	Entries []store.AuditEntry
	Check   store.AuditCheck
	Q       string
	Next    int64
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.FormValue("before"), 10, 64)
	q := strings.TrimSpace(r.FormValue("q"))
	if len(q) > 200 {
		q = q[:200]
	}
	list, err := s.store.AuditEntries(r.Context(), store.AuditFilter{Query: q, Before: before, Limit: 100})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	check, err := s.store.VerifyAudit(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := &auditData{Entries: list, Check: check, Q: q}
	if len(list) == 100 {
		d.Next = list[len(list)-1].ID
	}
	s.render(w, r, http.StatusOK, "audit", &Page{Title: "Audit log", Nav: "audit", Data: d})
}
