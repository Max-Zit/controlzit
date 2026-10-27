package web

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

// An agent counts as online when it was heard from in the last 3 minutes.
const onlineWindow = 3 * time.Minute

type overviewData struct {
	Counts    store.Counts
	Customers []store.Customer
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	c, err := s.store.Overview(r.Context(), u, s.now().Add(-onlineWindow))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	list, err := s.store.Customers(r.Context(), u)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(list) > 8 {
		list = list[:8]
	}
	s.render(w, r, http.StatusOK, "overview", &Page{Title: "Overview", Nav: "overview", Data: &overviewData{Counts: c, Customers: list}})
}

// ---- customers

type customersData struct {
	Customers []store.Customer
	Name      string
	Notes     string
}

func (s *Server) handleCustomers(w http.ResponseWriter, r *http.Request) {
	s.showCustomers(w, r, http.StatusOK, &customersData{}, "")
}

func (s *Server) showCustomers(w http.ResponseWriter, r *http.Request, status int, d *customersData, errMsg string) {
	list, err := s.store.Customers(r.Context(), userFrom(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Customers = list
	p := &Page{Title: "Customers", Nav: "customers", Data: d}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "customers", p)
}

func storeErr(err error) string {
	switch {
	case errors.Is(err, store.ErrConflict):
		return "This name is already used."
	case errors.Is(err, store.ErrInUse):
		return "It cannot be deleted while it still contains sites or devices."
	case errors.Is(err, store.ErrNotFound):
		return "Not found."
	}
	return err.Error()
}

func (s *Server) handleCustomerCreate(w http.ResponseWriter, r *http.Request) {
	if !userFrom(r).IsAdmin() {
		s.forbidden(w, r)
		return
	}
	d := &customersData{Name: r.FormValue("name"), Notes: r.FormValue("notes")}
	id, err := s.store.CreateCustomer(r.Context(), d.Name, d.Notes)
	if err != nil {
		s.showCustomers(w, r, http.StatusBadRequest, d, storeErr(err))
		return
	}
	s.audit(r, "customer.create", "customer:"+strconv.FormatInt(id, 10), "created customer %q", d.Name)
	if err := s.createDefaultPolicy(r.Context(), id, newCustomerPolicy(), defaultPolicyNote, s.issuer(r)); err != nil {
		s.log.Warn("cannot add the Default policy of a customer", "customer", id, "err", err)
	}
	s.redirect(w, r, "/customers/"+strconv.FormatInt(id, 10), "Customer created.")
}

// customerFor loads a customer the user may see, or answers 404.
func (s *Server) customerFor(w http.ResponseWriter, r *http.Request, id int64) *store.Customer {
	if !userFrom(r).SeesCustomer(id) {
		s.notFound(w, r)
		return nil
	}
	c, err := s.store.Customer(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, r)
		return nil
	}
	if err != nil {
		s.serverError(w, r, err)
		return nil
	}
	return c
}

type customerData struct {
	Customer *store.Customer
	Sites    []store.Site
	SiteName string
	Address  string
	Fields   []store.CustomField
	Policy   *store.Policy // assigned to the customer
}

func (s *Server) handleCustomer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	c := s.customerFor(w, r, id)
	if c == nil {
		return
	}
	s.showCustomer(w, r, http.StatusOK, &customerData{Customer: c}, "")
}

func (s *Server) showCustomer(w http.ResponseWriter, r *http.Request, status int, d *customerData, errMsg string) {
	sites, err := s.store.Sites(r.Context(), d.Customer.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Sites = sites
	d.Fields, _ = s.store.FieldValues(r.Context(), "customer", d.Customer.ID)
	d.Policy = s.assignedPolicy(r.Context(), "customer", d.Customer.ID)
	p := &Page{Title: d.Customer.Name, Nav: "customers", Data: d}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "customer", p)
}

func (s *Server) handleCustomerUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok || !userFrom(r).IsAdmin() {
		s.forbidden(w, r)
		return
	}
	c := s.customerFor(w, r, id)
	if c == nil {
		return
	}
	old := c.Name
	if err := s.store.UpdateCustomer(r.Context(), id, r.FormValue("name"), r.FormValue("notes")); err != nil {
		c.Name, c.Notes = r.FormValue("name"), r.FormValue("notes")
		s.showCustomer(w, r, http.StatusBadRequest, &customerData{Customer: c}, storeErr(err))
		return
	}
	s.audit(r, "customer.update", "customer:"+strconv.FormatInt(id, 10), "customer %q saved (name now %q)", old, r.FormValue("name"))
	s.redirect(w, r, "/customers/"+strconv.FormatInt(id, 10), "Saved.")
}

func (s *Server) handleCustomerDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok || !userFrom(r).IsAdmin() {
		s.forbidden(w, r)
		return
	}
	c := s.customerFor(w, r, id)
	if c == nil {
		return
	}
	if err := s.store.DeleteCustomer(r.Context(), id); err != nil {
		s.showCustomer(w, r, http.StatusConflict, &customerData{Customer: c}, storeErr(err))
		return
	}
	s.audit(r, "customer.delete", "customer:"+strconv.FormatInt(id, 10), "deleted customer %q", c.Name)
	s.redirect(w, r, "/customers", "Customer deleted.")
}

// ---- sites

func (s *Server) handleSiteCreate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok || !userFrom(r).CanWrite() {
		s.forbidden(w, r)
		return
	}
	c := s.customerFor(w, r, id)
	if c == nil {
		return
	}
	d := &customerData{Customer: c, SiteName: r.FormValue("name"), Address: r.FormValue("address")}
	sid, err := s.store.CreateSite(r.Context(), id, d.SiteName, d.Address, "")
	if err != nil {
		s.showCustomer(w, r, http.StatusBadRequest, d, storeErr(err))
		return
	}
	s.audit(r, "site.create", "site:"+strconv.FormatInt(sid, 10), "created site %q of customer %q", d.SiteName, c.Name)
	s.redirect(w, r, "/sites/"+strconv.FormatInt(sid, 10), "Site created.")
}

// siteFor loads a site whose customer the user may see.
func (s *Server) siteFor(w http.ResponseWriter, r *http.Request) *store.Site {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return nil
	}
	x, err := s.store.Site(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) || err == nil && !userFrom(r).SeesCustomer(x.CustomerID) {
		s.notFound(w, r)
		return nil
	}
	if err != nil {
		s.serverError(w, r, err)
		return nil
	}
	return x
}

type siteData struct {
	Site        *store.Site
	Policy      *store.Policy // assigned to the site
	Devices     []*store.Device
	Fingerprint string
	Tokens      []store.EnrollToken
	NewToken    string
	EnrollCode  string
	MSI         bool
	Linux       bool
	LinuxARM64  bool
	AgentURL    string
	AgentLocal  bool // the address is this machine only (console opened on localhost)
	Now         time.Time
	ValidDays   int
	MaxUses     int
}

func (s *Server) handleSite(w http.ResponseWriter, r *http.Request) {
	x := s.siteFor(w, r)
	if x == nil {
		return
	}
	s.showSite(w, r, http.StatusOK, &siteData{Site: x}, "")
}

func (s *Server) showSite(w http.ResponseWriter, r *http.Request, status int, d *siteData, errMsg string) {
	toks, err := s.store.EnrollTokens(r.Context(), d.Site.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Tokens, d.Now = toks, s.now()
	d.Policy = s.assignedPolicy(r.Context(), "site", d.Site.ID)
	if d.Devices, err = s.store.Devices(r.Context(), userFrom(r), store.DeviceFilter{SiteID: d.Site.ID}); err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Fingerprint = s.AgentFingerprint
	d.MSI = s.agentMSI() != ""
	d.Linux = s.download(AgentLinuxName) != ""
	d.LinuxARM64 = s.download(AgentLinuxARM64Name) != ""
	if d.ValidDays == 0 {
		d.ValidDays, d.MaxUses = 7, 50
	}
	d.AgentURL = s.agentURL(r)
	if u, err := url.Parse(d.AgentURL); err == nil {
		ip := net.ParseIP(u.Hostname())
		d.AgentLocal = u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
	}
	p := &Page{Title: d.Site.Name, Nav: "customers", Data: d}
	if errMsg != "" {
		p.Error = translate(s.lang(r, userFrom(r)), errMsg)
	}
	s.render(w, r, status, "site", p)
}

// agentURL is the address agents use: the configured public URL, or the
// console's host name with the agent port.
func (s *Server) agentURL(r *http.Request) string {
	n, err := s.Network(r.Context())
	if err == nil && n.PublicAgentURL != "" {
		return n.PublicAgentURL
	}
	_, port, _ := splitListen(n.AgentListen)
	if s.RunningAgent != "" {
		_, port, _ = splitListen(s.RunningAgent)
	}
	host := r.Host
	if h, _, err := splitHostPortLoose(host); err == nil {
		host = h
	}
	return "https://" + joinHostPort(host, strconv.Itoa(port))
}

func (s *Server) handleSiteUpdate(w http.ResponseWriter, r *http.Request) {
	x := s.siteFor(w, r)
	if x == nil {
		return
	}
	if !userFrom(r).CanWrite() {
		s.forbidden(w, r)
		return
	}
	if err := s.store.UpdateSite(r.Context(), x.ID, r.FormValue("name"), r.FormValue("address"), r.FormValue("notes")); err != nil {
		x.Name, x.Address, x.Notes = r.FormValue("name"), r.FormValue("address"), r.FormValue("notes")
		s.showSite(w, r, http.StatusBadRequest, &siteData{Site: x}, storeErr(err))
		return
	}
	s.audit(r, "site.update", "site:"+strconv.FormatInt(x.ID, 10), "site %q of customer %q saved", r.FormValue("name"), x.Customer)
	s.redirect(w, r, "/sites/"+strconv.FormatInt(x.ID, 10), "Saved.")
}

func (s *Server) handleSiteDelete(w http.ResponseWriter, r *http.Request) {
	x := s.siteFor(w, r)
	if x == nil {
		return
	}
	if !userFrom(r).CanWrite() {
		s.forbidden(w, r)
		return
	}
	if err := s.store.DeleteSite(r.Context(), x.ID); err != nil {
		s.showSite(w, r, http.StatusConflict, &siteData{Site: x}, storeErr(err))
		return
	}
	s.audit(r, "site.delete", "site:"+strconv.FormatInt(x.ID, 10), "deleted site %q of customer %q", x.Name, x.Customer)
	s.redirect(w, r, "/customers/"+strconv.FormatInt(x.CustomerID, 10), "Site deleted.")
}

// ---- enrollment tokens

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	x := s.siteFor(w, r)
	if x == nil {
		return
	}
	u := userFrom(r)
	if !u.CanWrite() {
		s.forbidden(w, r)
		return
	}
	days, err1 := strconv.Atoi(r.FormValue("days"))
	uses, err2 := strconv.Atoi(r.FormValue("uses"))
	d := &siteData{Site: x, ValidDays: days, MaxUses: uses}
	if err1 != nil || err2 != nil || days < 1 || days > 365 {
		s.showSite(w, r, http.StatusBadRequest, d, "An enrollment code must be valid between 1 and 365 days.")
		return
	}
	tok, err := s.store.CreateEnrollToken(r.Context(), x.ID, r.FormValue("label"), u.Username, time.Duration(days)*24*time.Hour, uses)
	if err != nil {
		s.showSite(w, r, http.StatusBadRequest, d, storeErr(err))
		return
	}
	s.audit(r, "token.create", "site:"+strconv.FormatInt(x.ID, 10), "enrollment token %q for site %q of %q: %d days, %d uses", r.FormValue("label"), x.Name, x.Customer, days, uses)
	// The token is shown once, in this response only.
	d.NewToken = tok
	d.EnrollCode = proto.MakeEnrollCode(proto.EnrollData{Server: s.agentURL(r), Fingerprint: s.AgentFingerprint, Token: tok})
	s.showSite(w, r, http.StatusOK, d, "")
}

func (s *Server) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	x := s.siteFor(w, r)
	if x == nil {
		return
	}
	tid, ok := pathID(r, "tid")
	if !ok || !userFrom(r).CanWrite() {
		s.forbidden(w, r)
		return
	}
	if err := s.store.RevokeEnrollToken(r.Context(), x.ID, tid); err != nil {
		s.showSite(w, r, http.StatusBadRequest, &siteData{Site: x}, storeErr(err))
		return
	}
	s.audit(r, "token.revoke", "site:"+strconv.FormatInt(x.ID, 10), "revoked enrollment token #%d of site %q", tid, x.Name)
	s.redirect(w, r, "/sites/"+strconv.FormatInt(x.ID, 10), "Enrollment code revoked.")
}

func splitHostPortLoose(hp string) (string, string, error) { return net.SplitHostPort(hp) }

func joinHostPort(h, p string) string { return net.JoinHostPort(strings.Trim(h, "[]"), p) }

// Online is used by the device list of the site page.
func (d *siteData) Online(x *store.Device) bool { return x.Online(d.Now, onlineWindow) }

// The Linux agents offered for download (64-bit x86 and ARM).
const (
	AgentLinuxName      = "controlzit-agent-linux-amd64"
	AgentLinuxARM64Name = "controlzit-agent-linux-arm64"
)

// download returns the path of a file in the downloads folder, or "".
func (s *Server) download(name string) string {
	if s.DownloadsDir == "" {
		return ""
	}
	p := filepath.Join(s.DownloadsDir, name)
	if st, err := os.Stat(p); err != nil || !st.Mode().IsRegular() {
		return ""
	}
	return p
}

func (s *Server) agentLinux(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := s.download(name)
		if p == "" {
			s.notFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		http.ServeFile(w, r, p)
	}
}

// AgentMSIName is the installer the console offers for download; put it
// into <data-dir>/downloads (release packages will do this).
const AgentMSIName = "controlzit-agent-x64.msi"

func (s *Server) agentMSI() string {
	if s.DownloadsDir == "" {
		return ""
	}
	p := filepath.Join(s.DownloadsDir, AgentMSIName)
	if st, err := os.Stat(p); err != nil || !st.Mode().IsRegular() {
		return ""
	}
	return p
}

func (s *Server) handleAgentMSI(w http.ResponseWriter, r *http.Request) {
	p := s.agentMSI()
	if p == "" {
		s.notFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-msi")
	w.Header().Set("Content-Disposition", `attachment; filename="`+AgentMSIName+`"`)
	http.ServeFile(w, r, p)
}
