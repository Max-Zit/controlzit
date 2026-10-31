package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/max-zit/rmmzit/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

//go:embed i18n/*.json
var i18nFS embed.FS

// Language is a console language.
type Language struct{ Code, Name string }

// Languages the console offers, by their own names; English is the source
// language.
var Languages = []Language{
	{"en", "English"}, {"de", "Deutsch"}, {"fr", "Français"}, {"es", "Español"}, {"it", "Italiano"},
	{"pt", "Português"}, {"nl", "Nederlands"}, {"pl", "Polski"}, {"cs", "Čeština"}, {"sr", "Srpski"},
	{"tr", "Türkçe"}, {"ru", "Русский"}, {"zh", "中文（简体）"}, {"ja", "日本語"},
}

// catalogs maps language → English text → translation.
var catalogs = map[string]map[string]string{}

func init() {
	for _, l := range Languages[1:] {
		raw, err := i18nFS.ReadFile("i18n/" + l.Code + ".json")
		if err != nil {
			panic(err)
		}
		m := map[string]string{}
		if err := json.Unmarshal(raw, &m); err != nil {
			panic(fmt.Sprintf("i18n/%s.json: %v", l.Code, err))
		}
		catalogs[l.Code] = m
	}
}

func validLang(code string) bool {
	for _, l := range Languages {
		if l.Code == code {
			return true
		}
	}
	return false
}

// translate returns the text in lang; with args it is a format string.
func translate(lang, key string, args ...any) string {
	if t, ok := catalogs[lang][key]; ok && t != "" {
		key = t
	}
	if len(args) > 0 {
		return fmt.Sprintf(key, args...)
	}
	return key
}

// Page is what every template gets.
type Page struct {
	Title      string
	Nav        string
	Lang       string
	User       *store.User
	Flash      string
	FlashErr   bool // the flash message reports a failure
	Error      string
	Version    string
	DevNo2FA   bool
	Asset      string
	AlertCount int
	Path       string
	Data       any
	// activeTasks counts the queued and running tasks of a device (the
	// Activity tab shows the number).
	activeTasks func(deviceID int64) int
	// CSRF-free forms post back to the same origin; nothing else needed.
}

// T translates a text for the page language.
func (p *Page) T(key string, args ...any) string { return translate(p.Lang, key, args...) }

// ActiveTasks is the number of queued and running tasks of a device.
func (p *Page) ActiveTasks(deviceID int64) int {
	if p.activeTasks == nil {
		return 0
	}
	return p.activeTasks(deviceID)
}

// TaskText translates the title or result of a task.
func (p *Page) TaskText(key string, args []string) string { return taskText(p.Lang, key, args) }

// Languages lists the console languages (for the language menu).
func (p *Page) Languages() []Language { return Languages }

// Time formats a time in the server's zone.
func (p *Page) Time(t any) string {
	switch v := t.(type) {
	case time.Time:
		if v.IsZero() {
			return "—"
		}
		return v.Local().Format("2006-01-02 15:04")
	case *time.Time:
		if v == nil || v.IsZero() {
			return "—"
		}
		return v.Local().Format("2006-01-02 15:04")
	case string: // RFC 3339, as agents send times
		if ts, err := time.Parse(time.RFC3339, v); err == nil {
			return p.Time(ts)
		}
		return "—"
	}
	return ""
}

// RoleName is the display name of a role.
func (p *Page) RoleName(r string) string {
	switch r {
	case store.RoleAdmin:
		return p.T("Administrator")
	case store.RoleTechnician:
		return p.T("Technician")
	case store.RoleReadOnly:
		return p.T("Read-only")
	}
	return r
}

var funcs = template.FuncMap{
	"initial": func(s string) string {
		for _, r := range s {
			return strings.ToUpper(string(r))
		}
		return "?"
	},
	"contains": func(list []int64, id int64) bool {
		for _, x := range list {
			if x == id {
				return true
			}
		}
		return false
	},
	"join":        strings.Join,
	"containsDay": containsInt,
	"rowctx":      func(p *Page, row any) rowCtx { return rowCtx{P: p, Row: row} },
	"fieldsctx": func(p *Page, action string, f []store.CustomField) fieldsCtx {
		return fieldsCtx{P: p, Action: action, Fields: f}
	},
	"u64": func(n int64) uint64 {
		if n < 0 {
			return 0
		}
		return uint64(n)
	},
	"powerPop": func(p *Page, action string) powerPop { return powerPop{P: p, Action: action} },
	"groupMapping": func(p *Page, g GroupMapping, lines string) groupMappingData {
		return groupMappingData{P: p, G: g, Lines: lines}
	},
	"userTable": func(p *Page, us []*store.User) userTable { return userTable{P: p, Users: us} },
	"roleForm": func(p *Page, role string, all bool, ids []int64, cs []store.Customer) roleForm {
		return roleForm{P: p, Role: role, All: all, IDs: ids, Customers: cs}
	},
	"deref": func(p *int) int {
		if p == nil {
			return 0
		}
		return *p
	},
	"deref64": func(p *int64) int64 {
		if p == nil {
			return 0
		}
		return *p
	},
	"add":   func(a, b int) int { return a + b },
	"clock": func(m int) string { return fmt.Sprintf("%02d:%02d", m/60, m%60) },
	"firstLine": func(s string) string {
		s = strings.TrimSpace(s)
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			return s[:i] + " …"
		}
		return s
	},
	"seq": func(a, b int) []int {
		var out []int
		for i := a; i <= b; i++ {
			out = append(out, i)
		}
		return out
	},
	"shellName": shellName,
	"weekday":   func(d int) string { return time.Weekday(d).String() },
	"wuResult": func(code int) string {
		switch code {
		case 2:
			return "succeeded"
		case 3:
			return "succeeded with errors"
		case 4:
			return "failed"
		case 5:
			return "aborted"
		case 1:
			return "in progress"
		}
		return "not started"
	},
	"devtabs": func(p *Page, d *store.Device, cur string) devTabs { return devTabs{P: p, D: d, Cur: cur} },
}

// loadTemplates parses each page together with the layout.
func loadTemplates() (map[string]*template.Template, error) {
	base, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/_*.html")
	if err != nil {
		return nil, err
	}
	pages, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	out := map[string]*template.Template{}
	for _, p := range pages {
		name := strings.TrimSuffix(strings.TrimPrefix(p, "templates/"), ".html")
		if strings.HasPrefix(name, "_") {
			continue
		}
		t, err := template.Must(base.Clone()).ParseFS(templateFS, p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out[name] = t
	}
	return out, nil
}

// render writes a page; the layout is chosen by the page itself
// ({{template "app" .}} or {{template "guest" .}}).
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, p *Page) {
	t, ok := s.tmpl[name]
	if !ok {
		s.serverError(w, r, fmt.Errorf("no template %q", name))
		return
	}
	if p.User == nil {
		p.User = userFrom(r)
	}
	if p.Lang == "" {
		p.Lang = s.lang(r, p.User) // the user's own language first
	}
	p.Version = s.Version
	p.DevNo2FA = s.DevNo2FA
	p.Asset = assetVersion
	p.Path = r.URL.RequestURI()
	if p.User != nil {
		p.AlertCount, _ = s.store.OpenAlertCount(r.Context(), p.User)
	}
	p.activeTasks = func(id int64) int {
		n, _ := s.store.ActiveTasks(r.Context(), id)
		return n
	}
	if f := s.takeFlash(w, r); f != "" && p.Flash == "" {
		// An error message (redirectErr) starts with "!".
		p.Flash, p.FlashErr = strings.TrimPrefix(f, "!"), strings.HasPrefix(f, "!")
	}
	var b strings.Builder
	if err := t.ExecuteTemplate(&b, name+".html", p); err != nil {
		s.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(b.String()))
}

// lang picks the console language: the user's choice, the lang cookie,
// then the browser's preference.
func (s *Server) lang(r *http.Request, u *store.User) string {
	if u != nil && validLang(u.Lang) {
		return u.Lang
	}
	if c, err := r.Cookie("lang"); err == nil && validLang(c.Value) {
		return c.Value
	}
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		code := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		code = strings.SplitN(code, "-", 2)[0]
		if code == "sr" || code == "hr" || code == "bs" || code == "sh" {
			return "sr"
		}
		if validLang(code) {
			return code
		}
	}
	return "en"
}

// ---- flash messages: a short-lived cookie carries the message (in
// English, translated when shown) across the redirect after a POST.

const flashCookie = "czflash"

func (s *Server) flash(w http.ResponseWriter, r *http.Request, msg string) {
	// #nosec G124 -- Secure whenever the request came over TLS; plain HTTP is only the loopback dev listener
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: url.QueryEscape(msg), Path: "/", MaxAge: 60,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
}

func (s *Server) takeFlash(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie(flashCookie)
	if err != nil {
		return ""
	}
	// #nosec G124 -- Secure whenever the request came over TLS; plain HTTP is only the loopback dev listener
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	msg, _ := url.QueryUnescape(c.Value)
	if len(msg) > 300 {
		return ""
	}
	if strings.HasPrefix(msg, "!") {
		return msg // an error, translated when it was set
	}
	return translate(s.lang(r, userFrom(r)), msg)
}

// redirect answers a POST with 303 See Other and an optional message.
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, to, msg string) {
	if msg != "" {
		s.flash(w, r, msg)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// roleForm feeds the shared role/access fields of the user forms.
type roleForm struct {
	P         *Page
	Role      string
	All       bool
	IDs       []int64
	Customers []store.Customer
}

// assetVersion changes with the static files, so browsers do not keep an
// old app.css or app.js from their cache after an update.
var assetVersion = func() string {
	h := sha256.New()
	for _, f := range []string{"static/app.css", "static/app.js", "static/rd.js", "static/term.js"} {
		b, _ := staticFS.ReadFile(f)
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}()

// devTabs feeds the section menu of a device.
type devTabs struct {
	P   *Page
	D   *store.Device
	Cur string
}

// renderString renders a page template to a string (emails).
func (s *Server) renderString(name string, p *Page) (string, error) {
	t, ok := s.tmpl[name]
	if !ok {
		return "", fmt.Errorf("no template %q", name)
	}
	var b strings.Builder
	if err := t.ExecuteTemplate(&b, name+".html", p); err != nil {
		return "", err
	}
	return b.String(), nil
}

func shellName(s string) string {
	return map[string]string{"powershell": "PowerShell", "cmd": "cmd", "bash": "bash", "sh": "sh", "package": "MSI / EXE"}[s]
}

// rowCtx is a row of a form template together with its page.
type rowCtx struct {
	P   *Page
	Row any
}

// fieldsCtx is the custom fields panel of a device or customer.
type fieldsCtx struct {
	P      *Page
	Action string
	Fields []store.CustomField
}
