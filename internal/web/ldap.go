package web

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/max-zit/controlzit/internal/store"
)

// Sign-in with Active Directory or another LDAP directory (Settings →
// Active Directory / LDAP). The directory checks the password; ControlZit
// still asks for its own second factor. Roles and customers follow the
// groups at every sign-in.

const settingLDAP = "ldap"

// LDAPSettings configure the directory.
type LDAPSettings struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"` // ldaps://dc1.example.local or ldap://…:389 with StartTLS
	// StartTLS upgrades an ldap:// connection (required for ldap://).
	StartTLS bool `json:"starttls"`
	// CACert (PEM) trusts a company CA; empty = the system's CAs.
	CACert       string `json:"ca_cert,omitempty"`
	BindDN       string `json:"bind_dn"`
	BindPassword string `json:"bind_password,omitempty"` // sealed
	BaseDN       string `json:"base_dn"`
	// UserFilter finds the user; {username} is replaced (escaped).
	UserFilter string `json:"user_filter"`
	// NestedGroups follows groups in groups (Active Directory).
	NestedGroups bool         `json:"nested_groups"`
	Groups       GroupMapping `json:"groups"`
}

// The usual filters.
const (
	adUserFilter   = "(&(objectClass=user)(sAMAccountName={username}))"
	ldapUserFilter = "(&(objectClass=inetOrgPerson)(uid={username}))"
)

// Validate checks the settings.
func (c *LDAPSettings) Validate() error {
	if !c.Enabled {
		return nil
	}
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "ldaps" && u.Scheme != "ldap") || u.Hostname() == "" {
		return uiErr("The server address must look like ldaps://dc1.example.local (or ldap://dc1.example.local with StartTLS).")
	}
	if u.Scheme == "ldap" && !c.StartTLS {
		return uiErr("An ldap:// address needs StartTLS: passwords must not cross the network unencrypted.")
	}
	if c.CACert != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CACert)) {
		return uiErr("The CA certificate must be in PEM format (-----BEGIN CERTIFICATE-----).")
	}
	if c.BindDN == "" || c.BaseDN == "" {
		return uiErr("Enter the service account and the base DN.")
	}
	if !strings.Contains(c.UserFilter, "{username}") {
		return uiErr("The user filter must contain {username}.")
	}
	return c.Groups.validate()
}

// LDAP loads the settings (the bind password sealed).
func (s *Server) LDAP(ctx context.Context) LDAPSettings {
	c := LDAPSettings{UserFilter: adUserFilter, NestedGroups: true, Groups: GroupMapping{AllByDefault: true}}
	_ = s.store.GetSetting(ctx, settingLDAP, &c)
	return c
}

func (s *Server) ldapPassword(c LDAPSettings) string {
	if c.BindPassword == "" {
		return ""
	}
	p, _ := s.store.OpenSecret("settings.ldap.bind", c.BindPassword)
	return p
}

// ldapAccount is a user as the directory knows it.
type ldapAccount struct {
	DN, Username, DisplayName, Email string
	Groups                           []string
}

var errLDAPCredentials = errors.New("wrong username or password")

// ldapConnect opens an encrypted connection.
func ldapConnect(c LDAPSettings) (*ldap.Conn, error) {
	u, _ := url.Parse(c.URL)
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if c.CACert != "" {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(c.CACert))
		tc.RootCAs = pool
	}
	conn, err := ldap.DialURL(c.URL, ldap.DialWithTLSConfig(tc), ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}))
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(15 * time.Second)
	if u.Scheme == "ldap" {
		if err := conn.StartTLS(tc); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// ldapAuthenticate checks a user's password in the directory and reads
// its groups.
func ldapAuthenticate(c LDAPSettings, bindPassword, username, password string) (*ldapAccount, error) {
	if username == "" || password == "" {
		return nil, errLDAPCredentials // an empty password would be an anonymous bind
	}
	conn, err := ldapConnect(c)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.Bind(c.BindDN, bindPassword); err != nil {
		return nil, uiErrf("The service account cannot sign in to the directory: %v", err)
	}
	filter := strings.ReplaceAll(c.UserFilter, "{username}", ldap.EscapeFilter(username))
	res, err := conn.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 15, false, filter,
		[]string{"displayName", "cn", "mail", "memberOf", "sAMAccountName", "uid"}, nil))
	if err != nil {
		return nil, err
	}
	if len(res.Entries) != 1 {
		return nil, errLDAPCredentials
	}
	e := res.Entries[0]
	if err := conn.Bind(e.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, errLDAPCredentials
		}
		return nil, err
	}
	a := &ldapAccount{DN: e.DN, DisplayName: e.GetAttributeValue("displayName"), Email: e.GetAttributeValue("mail"), Groups: e.GetAttributeValues("memberOf")}
	if a.DisplayName == "" {
		a.DisplayName = e.GetAttributeValue("cn")
	}
	a.Username = e.GetAttributeValue("sAMAccountName")
	if a.Username == "" {
		a.Username = e.GetAttributeValue("uid")
	}
	if a.Username == "" {
		a.Username = username
	}
	if len(a.Groups) == 0 {
		// Directories without memberOf (plain OpenLDAP): the groups that
		// list the user. Back to the service account, which may read them.
		if err := conn.Bind(c.BindDN, bindPassword); err == nil {
			f := "(|(member=" + ldap.EscapeFilter(e.DN) + ")(uniqueMember=" + ldap.EscapeFilter(e.DN) + ")(memberUid=" + ldap.EscapeFilter(a.Username) + "))"
			if res, err := conn.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 500, 15, false, f, []string{"dn"}, nil)); err == nil {
				for _, g := range res.Entries {
					a.Groups = append(a.Groups, g.DN)
				}
			}
		}
	}
	if c.NestedGroups {
		// Active Directory: every group the user is in, directly or through
		// other groups (LDAP_MATCHING_RULE_IN_CHAIN). Back to the service
		// account, which may read groups.
		if err := conn.Bind(c.BindDN, bindPassword); err == nil {
			res, err := conn.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 500, 15, false,
				"(member:1.2.840.113556.1.4.1941:="+ldap.EscapeFilter(e.DN)+")", []string{"dn"}, nil))
			if err == nil {
				seen := map[string]bool{}
				for _, g := range a.Groups {
					seen[strings.ToLower(g)] = true
				}
				for _, g := range res.Entries {
					if !seen[strings.ToLower(g.DN)] {
						a.Groups = append(a.Groups, g.DN)
					}
				}
			}
		}
	}
	return a, nil
}

// ldapSignIn tries the directory for a sign-in. ok is false when the
// directory is not used for this username.
func (s *Server) ldapSignIn(ctx context.Context, username, password string) (u *store.User, ok bool, err error) {
	c := s.LDAP(ctx)
	if !c.Enabled {
		return nil, false, nil
	}
	if src := s.store.UserSource(ctx, username); src != "" && src != "ldap" {
		return nil, false, nil
	}
	a, err := ldapAuthenticate(c, s.ldapPassword(c), username, password)
	if err != nil {
		return nil, true, err
	}
	role, all, ids, err := s.resolve(ctx, c.Groups, a.Groups)
	if err != nil {
		return nil, true, err
	}
	u, err = s.store.UpsertDirectoryUser(ctx, store.DirectoryUser{Source: "ldap", Username: a.Username, DisplayName: a.DisplayName, Email: a.Email,
		Role: role, AllCustomers: all, CustomerIDs: ids})
	if err != nil {
		return nil, true, err
	}
	if u.Disabled {
		return nil, true, errLDAPCredentials
	}
	return u, true, nil
}

// ---- Settings → Active Directory / LDAP

type ldapData struct {
	S       LDAPSettings
	HasPass bool
	Groups  string
	Test    *ldapTestResult
}

type ldapTestResult struct {
	OK        bool
	Error     string
	DN        string
	Username  string
	Name      string
	Groups    []string
	Role      string
	Customers string
}

func (s *Server) handleLDAPSettings(w http.ResponseWriter, r *http.Request) {
	s.showLDAP(w, r, nil)
}

func (s *Server) showLDAP(w http.ResponseWriter, r *http.Request, test *ldapTestResult) {
	c := s.LDAP(r.Context())
	d := &ldapData{S: c, HasPass: c.BindPassword != "", Groups: strings.Join(c.Groups.CustomerGroups, "\n"), Test: test}
	d.S.BindPassword = ""
	s.render(w, r, http.StatusOK, "ldap", &Page{Title: "Active Directory / LDAP", Nav: "settings", Data: d})
}

func (s *Server) handleLDAPSave(w http.ResponseWriter, r *http.Request) {
	old := s.LDAP(r.Context())
	c := LDAPSettings{Enabled: r.FormValue("enabled") == "1", URL: strings.TrimSpace(r.FormValue("url")), StartTLS: r.FormValue("starttls") == "1",
		CACert: strings.TrimSpace(r.FormValue("ca_cert")), BindDN: strings.TrimSpace(r.FormValue("bind_dn")), BaseDN: strings.TrimSpace(r.FormValue("base_dn")),
		UserFilter: strings.TrimSpace(r.FormValue("user_filter")), NestedGroups: r.FormValue("nested") == "1", BindPassword: old.BindPassword,
		Groups: mappingFromForm(r.FormValue)}
	if p := r.FormValue("bind_password"); p != "" {
		c.BindPassword = s.store.SealSecret("settings.ldap.bind", p)
	}
	if c.Enabled && c.BindPassword == "" {
		s.redirectErr(w, r, "/settings/ldap", uiErr("Enter the password of the service account."))
		return
	}
	if err := c.Validate(); err != nil {
		s.redirectErr(w, r, "/settings/ldap", err)
		return
	}
	if err := s.store.SetSetting(r.Context(), settingLDAP, c); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.ldap", "settings", "directory sign-in: %v, %s, base %s, groups admin %q technician %q read-only %q default %q",
		c.Enabled, c.URL, c.BaseDN, c.Groups.AdminGroup, c.Groups.TechnicianGroup, c.Groups.ReadOnlyGroup, c.Groups.DefaultRole)
	s.redirect(w, r, "/settings/ldap", "Saved.")
}

// handleLDAPTest signs a user in against the directory without opening a
// session, and shows what ControlZit would make of the account.
func (s *Server) handleLDAPTest(w http.ResponseWriter, r *http.Request) {
	c := s.LDAP(r.Context())
	res := &ldapTestResult{}
	user := strings.TrimSpace(r.FormValue("test_user"))
	a, err := ldapAuthenticate(c, s.ldapPassword(c), user, r.FormValue("test_password"))
	if err == nil {
		res.DN, res.Username, res.Name, res.Groups = a.DN, a.Username, a.DisplayName, a.Groups
		role, all, ids, rerr := s.resolve(r.Context(), c.Groups, a.Groups)
		if rerr != nil {
			err = rerr
		} else {
			res.OK, res.Role = true, role
			res.Customers = s.customerNames(r.Context(), all, ids)
		}
	}
	if err != nil {
		res.Error = s.errText(r, err)
	}
	s.audit(r, "settings.ldap.test", "settings", "directory test for %q: ok %v %s", user, res.OK, res.Error)
	s.showLDAP(w, r, res)
}
