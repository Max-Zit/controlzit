package web_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/controlzit/internal/auth"
	"github.com/max-zit/controlzit/internal/store"
	"github.com/max-zit/controlzit/internal/testdb"
	"github.com/max-zit/controlzit/internal/web"
)

func TestMain(m *testing.M) { os.Exit(testdb.Main(m)) }

type env struct {
	t     *testing.T
	st    *store.Store
	srv   *web.Server
	h     http.Handler
	now   time.Time
	setup string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	st.UseSecretKey(bytes.Repeat([]byte{3}, 32))
	srv, err := web.New(ctx, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, st: st, srv: srv, now: time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC), setup: "setup-secret"}
	srv.SetClock(func() time.Time { return e.now })
	st.SetClock(func() time.Time { return e.now })
	srv.SetSetupToken(e.setup)
	e.h = srv.Handler()
	return e
}

// client is a browser: cookies, a source address, same-origin posts.
type client struct {
	e       *env
	ip      string
	cookies map[string]string
}

func (e *env) client(ip string) *client { return &client{e: e, ip: ip, cookies: map[string]string{}} }

type resp struct {
	code int
	loc  string
	body string
}

func (c *client) do(method, path string, form url.Values, hdr map[string]string) resp {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, "http://cz.test"+path, body)
	r.RemoteAddr = c.ip + ":50000"
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if method == http.MethodPost {
		r.Header.Set("Origin", "http://cz.test")
	}
	for k, v := range hdr {
		if v == "" {
			r.Header.Del(k)
		} else {
			r.Header.Set(k, v)
		}
	}
	for k, v := range c.cookies {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	w := httptest.NewRecorder()
	c.e.h.ServeHTTP(w, r)
	for _, ck := range w.Result().Cookies() {
		if ck.MaxAge < 0 {
			delete(c.cookies, ck.Name)
		} else {
			c.cookies[ck.Name] = ck.Value
		}
	}
	return resp{code: w.Code, loc: w.Header().Get("Location"), body: w.Body.String()}
}

func (c *client) get(path string) resp { return c.do(http.MethodGet, path, nil, nil) }
func (c *client) post(path string, kv ...string) resp {
	f := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		f.Add(kv[i], kv[i+1])
	}
	return c.do(http.MethodPost, path, f, nil)
}

var secretRE = regexp.MustCompile(`<code class="secret"[^>]*>([A-Z2-7]+)</code>`)

func (e *env) code(secret string) string {
	c, _ := auth.TOTPCode(secret, e.now.Unix()/30)
	return c
}

// setupAdmin runs the first-run setup and the 2FA enrollment; it returns
// the signed-in client and the TOTP secret.
func (e *env) setupAdmin(ip string) (*client, string) {
	e.t.Helper()
	c := e.client(ip)
	r := c.post("/setup", "token", e.setup, "username", "admin", "password", "admin password 123", "password2", "admin password 123")
	if r.code != http.StatusSeeOther || r.loc != "/login/enroll" {
		e.t.Fatalf("setup: %d %s %s", r.code, r.loc, r.body)
	}
	r = c.get("/login/enroll")
	m := secretRE.FindStringSubmatch(r.body)
	if m == nil {
		e.t.Fatalf("no secret on the enrollment page: %s", r.body)
	}
	r = c.post("/login/enroll", "code", e.code(m[1]))
	if r.code != http.StatusOK || !strings.Contains(r.body, `class="codes"`) {
		e.t.Fatalf("enroll: %d %s", r.code, r.body)
	}
	e.now = e.now.Add(31 * time.Second)
	return c, m[1]
}

func TestSetupRequiresTokenAnd2FA(t *testing.T) {
	e := newEnv(t)
	c := e.client("192.168.1.10")
	if r := c.get("/"); r.loc != "/setup" {
		t.Fatalf("fresh server should send to setup, got %d %s", r.code, r.loc)
	}
	r := c.post("/setup", "token", "wrong", "username", "admin", "password", "admin password 123", "password2", "admin password 123")
	if r.code != http.StatusBadRequest {
		t.Fatalf("wrong setup token accepted: %d", r.code)
	}
	if n, _ := e.st.UserCount(context.Background()); n != 0 {
		t.Fatal("user created with a wrong token")
	}
	c2 := e.client("192.168.1.11")
	r = c2.post("/setup", "token", e.setup, "username", "admin", "password", "admin password 123", "password2", "admin password 123")
	if r.loc != "/login/enroll" {
		t.Fatalf("setup: %d %s", r.code, r.loc)
	}
	// Before the second factor is confirmed the console stays closed.
	if r := c2.get("/customers"); r.code != http.StatusSeeOther || !strings.HasPrefix(r.loc, "/login") {
		t.Fatalf("console open before 2FA: %d %s", r.code, r.loc)
	}
	// Setup cannot run twice.
	if r := c.post("/setup", "token", e.setup, "username", "evil", "password", "evil password 123", "password2", "evil password 123"); r.loc != "/login" {
		t.Fatalf("second setup: %d %s", r.code, r.loc)
	}
}

func TestLoginWith2FA(t *testing.T) {
	e := newEnv(t)
	_, secret := e.setupAdmin("192.168.1.10")
	c := e.client("192.168.1.20")
	r := c.post("/login", "username", "admin", "password", "admin password 123")
	if r.loc != "/login/2fa?next=%2F" {
		t.Fatalf("login: %d %s", r.code, r.loc)
	}
	if r := c.get("/"); r.code != http.StatusSeeOther {
		t.Fatal("password alone opened the console")
	}
	pre := c.cookies["czsession"]
	if r := c.post("/login/2fa", "code", "000000"); r.code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", r.code)
	}
	code := e.code(secret)
	if r := c.post("/login/2fa", "code", code, "next", "/customers"); r.loc != "/customers" {
		t.Fatalf("2fa: %d %s %s", r.code, r.loc, r.body)
	}
	if c.cookies["czsession"] == pre {
		t.Fatal("session token not rotated after the second factor")
	}
	if r := c.get("/customers"); r.code != http.StatusOK {
		t.Fatalf("console after sign-in: %d", r.code)
	}
	// The same code cannot be used again (replay).
	c3 := e.client("192.168.1.21")
	c3.post("/login", "username", "admin", "password", "admin password 123")
	if r := c3.post("/login/2fa", "code", code); r.code != http.StatusUnauthorized {
		t.Fatalf("replayed TOTP code accepted: %d", r.code)
	}
	// Sign out ends the session.
	c.post("/logout")
	if r := c.get("/customers"); r.code != http.StatusSeeOther {
		t.Fatal("still signed in after logout")
	}
	// Open redirect is refused.
	c4 := e.client("192.168.1.22")
	c4.post("/login", "username", "admin", "password", "admin password 123")
	e.now = e.now.Add(31 * time.Second)
	if r := c4.post("/login/2fa", "code", e.code(secret), "next", "//evil.example/x"); r.loc != "/" {
		t.Fatalf("open redirect: %s", r.loc)
	}
}

func TestCSRF(t *testing.T) {
	e := newEnv(t)
	c, _ := e.setupAdmin("192.168.1.10")
	f := url.Values{"name": {"Evil"}}
	for _, h := range []map[string]string{
		{"Origin": "http://evil.example"},
		{"Origin": "", "Referer": ""},
		{"Origin": "http://cz.test", "Sec-Fetch-Site": "cross-site"},
	} {
		if r := c.do(http.MethodPost, "/customers", f, h); r.code != http.StatusForbidden {
			t.Errorf("cross-site post %v: %d", h, r.code)
		}
	}
	if r := c.do(http.MethodPost, "/customers", f, map[string]string{"Origin": "", "Referer": "http://cz.test/customers"}); r.code != http.StatusSeeOther {
		t.Errorf("same-origin Referer refused: %d", r.code)
	}
}

func TestManagementAllowList(t *testing.T) {
	e := newEnv(t)
	c, _ := e.setupAdmin("192.168.1.10")
	// Public addresses are refused by default.
	if r := e.client("203.0.113.5").get("/login"); r.code != http.StatusForbidden {
		t.Fatalf("public address reached the console: %d", r.code)
	}
	// A list that would lock out the saving administrator is refused.
	r := c.post("/settings/network", "mgmt_listen", ":8443", "agent_listen", ":8444", "mgmt_allowed", "10.0.0.0/8")
	if r.code != http.StatusBadRequest || !strings.Contains(r.body, "lock you out") {
		t.Fatalf("lock-out list accepted: %d", r.code)
	}
	// Same port for both listeners is refused.
	if r := c.post("/settings/network", "mgmt_listen", ":8443", "agent_listen", ":8443", "mgmt_allowed", "192.168.1.0/24"); r.code != http.StatusBadRequest {
		t.Fatalf("same port accepted: %d", r.code)
	}
	r = c.post("/settings/network", "mgmt_listen", ":8443", "agent_listen", ":9444", "mgmt_allowed", "192.168.1.0/24\n203.0.113.5", "agent_allowed", "")
	if r.code != http.StatusSeeOther {
		t.Fatalf("save network: %d %s", r.code, r.body)
	}
	if r := e.client("203.0.113.5").get("/login"); r.code != http.StatusOK {
		t.Fatalf("newly allowed address refused: %d", r.code)
	}
	if r := e.client("10.1.1.1").get("/login"); r.code != http.StatusForbidden {
		t.Fatalf("removed network still allowed: %d", r.code)
	}
	if r := e.client("127.0.0.1").get("/login"); r.code != http.StatusOK {
		t.Fatal("loopback must always reach the console")
	}
	if err := web.ResetMgmtAllowList(context.Background(), e.st); err != nil {
		t.Fatal(err)
	}
	n, _ := e.srv.Network(context.Background())
	if n.AgentListen != ":9444" || strings.Join(n.MgmtAllowed, ",") != "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7" {
		t.Fatalf("reset: %+v", n)
	}
	// The agent endpoint is open to all by default and has its own handler.
	ag := e.srv.AgentHandler()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/agent/v1/health", nil)
	req.RemoteAddr = "198.51.100.7:1234"
	ag.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("agent health: %d", w.Code)
	}
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/login", nil)
	req.RemoteAddr = "198.51.100.7:1234"
	ag.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("console reachable on the agent listener: %d", w.Code)
	}
}

func TestLoginBlock(t *testing.T) {
	e := newEnv(t)
	e.setupAdmin("192.168.1.10")
	c := e.client("192.168.1.66")
	for i := 0; i < 5; i++ {
		c.post("/login", "username", "admin", "password", "wrong password!")
	}
	r := c.post("/login", "username", "admin", "password", "admin password 123")
	if r.code != http.StatusTooManyRequests {
		t.Fatalf("blocked address could sign in: %d", r.code)
	}
	// Loopback is never blocked.
	l := e.client("127.0.0.1")
	for i := 0; i < 6; i++ {
		l.post("/login", "username", "nobody", "password", "wrong password!")
	}
	if r := l.post("/login", "username", "admin", "password", "admin password 123"); r.code != http.StatusSeeOther {
		t.Fatalf("loopback blocked: %d", r.code)
	}
	e.st.Unblock(context.Background(), "192.168.1.66")
	if r := c.post("/login", "username", "admin", "password", "admin password 123"); r.code != http.StatusSeeOther {
		t.Fatalf("unblocked address refused: %d", r.code)
	}
}

var idRE = regexp.MustCompile(`/(\d+)$`)

func TestRolesAndCustomerVisibility(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin("192.168.1.10")
	r := admin.post("/customers", "name", "Acme")
	acme := idRE.FindStringSubmatch(r.loc)[1]
	r = admin.post("/customers", "name", "Beta")
	beta := idRE.FindStringSubmatch(r.loc)[1]
	r = admin.post("/customers/"+acme+"/sites", "name", "HQ")
	if r.code != http.StatusSeeOther {
		t.Fatalf("site: %d %s", r.code, r.body)
	}
	site := idRE.FindStringSubmatch(r.loc)[1]
	r = admin.post("/users", "username", "tech", "password", "tech password 123", "role", "technician", "customers", beta)
	if r.code != http.StatusSeeOther {
		t.Fatalf("create user: %d %s", r.code, r.body)
	}

	tech := e.client("192.168.1.30")
	tech.post("/login", "username", "tech", "password", "tech password 123")
	r = tech.get("/login/enroll")
	sec := secretRE.FindStringSubmatch(r.body)[1]
	tech.post("/login/enroll", "code", e.code(sec))
	// Must change the initial password first.
	if r := tech.get("/customers"); r.loc != "/account" {
		t.Fatalf("initial password not forced to change: %d %s", r.code, r.loc)
	}
	if r := tech.post("/account/password", "current", "tech password 123", "password", "my own password 1", "password2", "my own password 1"); r.code != http.StatusSeeOther {
		t.Fatalf("change password: %d %s", r.code, r.body)
	}
	r = tech.get("/customers")
	if !strings.Contains(r.body, "Beta") || strings.Contains(r.body, "Acme") {
		t.Fatal("technician sees the wrong customers")
	}
	if r := tech.get("/customers/" + acme); r.code != http.StatusNotFound {
		t.Fatalf("technician opened another customer: %d", r.code)
	}
	if r := tech.get("/sites/" + site); r.code != http.StatusNotFound {
		t.Fatalf("technician opened a site of another customer: %d", r.code)
	}
	if r := tech.post("/sites/"+site+"/tokens", "days", "7", "uses", "5"); r.code != http.StatusNotFound {
		t.Fatalf("technician made a token for another customer: %d", r.code)
	}
	for _, p := range []string{"/users", "/audit", "/settings/network", "/settings/security"} {
		if r := tech.get(p); r.code != http.StatusForbidden {
			t.Errorf("technician opened %s: %d", p, r.code)
		}
	}
	if r := tech.post("/customers", "name", "X"); r.code != http.StatusForbidden {
		t.Fatalf("technician created a customer: %d", r.code)
	}

	// Enrollment token: shown once, stored hashed, audited.
	r = admin.post("/sites/"+site+"/tokens", "label", "office", "days", "7", "uses", "10")
	tok := regexp.MustCompile(`czet_[A-Za-z0-9_-]{43}`).FindString(r.body)
	if r.code != http.StatusOK || tok == "" {
		t.Fatalf("token page: %d", r.code)
	}
	if r := admin.get("/sites/" + site); strings.Contains(r.body, tok) {
		t.Fatal("token shown again")
	}
	if id, err := e.st.UseEnrollToken(context.Background(), tok); err != nil || id <= 0 {
		t.Fatalf("token unusable: %v", err)
	}
	r = admin.get("/audit")
	for _, want := range []string{"token.create", "customer.create", "user.create", "account.password", "login", "chain of"} {
		if !strings.Contains(r.body, want) {
			t.Errorf("audit page lacks %q", want)
		}
	}
	if strings.Contains(r.body, tok) {
		t.Fatal("token value in the audit log")
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	r := httptest.NewRequest(http.MethodGet, "http://cz.test/setup", nil)
	r.RemoteAddr = "192.168.1.5:1"
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP: %q", csp)
	}
	if w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("security headers missing")
	}
	if strings.Contains(w.Body.String(), "<script>") || strings.Contains(w.Body.String(), " style=") || strings.Contains(w.Body.String(), "onclick") {
		t.Fatal("inline script or style in a page")
	}
}

func TestSerbianPages(t *testing.T) {
	e := newEnv(t)
	c := e.client("192.168.1.10")
	r := c.do(http.MethodGet, "/setup", nil, map[string]string{"Accept-Language": "sr-Latn-RS,sr;q=0.9,en;q=0.5"})
	if !strings.Contains(r.body, `lang="sr"`) || !strings.Contains(r.body, "Korisničko ime") {
		t.Fatalf("Serbian not chosen from Accept-Language")
	}
}

func TestDevNo2FA(t *testing.T) {
	e := newEnv(t)
	e.setupAdmin("192.168.1.10")
	c := e.client("192.168.1.40")
	if r := c.post("/login", "username", "admin", "password", "admin password 123"); !strings.HasPrefix(r.loc, "/login/2fa") {
		t.Fatalf("2FA skipped without dev mode: %s", r.loc)
	}
	e.srv.DevNo2FA = true
	c = e.client("192.168.1.41")
	r := c.post("/login", "username", "admin", "password", "admin password 123")
	if r.loc != "/" {
		t.Fatalf("dev mode login: %d %s", r.code, r.loc)
	}
	if r := c.get("/"); r.code != http.StatusOK || !strings.Contains(r.body, "--dev-no-2fa") {
		t.Fatalf("dev mode banner missing: %d", r.code)
	}
}
