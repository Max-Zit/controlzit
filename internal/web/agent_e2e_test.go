package web_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"html"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/max-zit/rmmzit/internal/agent"
	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/store"
	"github.com/max-zit/rmmzit/internal/tlsutil"
)

// agentServer runs the agent endpoint over real TLS with client certificates.
func agentServer(t *testing.T, e *env) (url, fingerprint string) {
	t.Helper()
	certPEM, keyPEM, err := tlsutil.SelfSigned("test agent endpoint", 1)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(e.srv.AgentHandler())
	ts.TLS = tlsutil.AgentServerConfig(cert)
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts.URL, tlsutil.Fingerprint(cert)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	waitForUpTo(t, what, 10*time.Second, cond)
}

func waitForUpTo(t *testing.T, what string, limit time.Duration, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(limit); time.Now().Before(end); {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestAgentEnrollConnectInventory(t *testing.T) {
	agent.ProtectDir = func(string) error { return nil }
	e := newEnv(t)
	e.useRealClock()
	ctx := context.Background()
	cust, _ := e.st.CreateCustomer(ctx, "Acme", "")
	site, _ := e.st.CreateSite(ctx, cust, "HQ", "", "")
	tok, _ := e.st.CreateEnrollToken(ctx, site, "", "admin", 24*time.Hour, 1)
	url, fp := agentServer(t, e)
	dir := t.TempDir()

	// A wrong pin is refused before anything is sent.
	bad := strings.Repeat("ab", 32)
	if _, err := agent.Enroll(ctx, dir, url, bad, tok); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("wrong fingerprint accepted: %v", err)
	}
	if _, err := agent.Enroll(ctx, dir, url, fp, "czet_wrong"); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("wrong token accepted: %v", err)
	}
	cfg, err := agent.Enroll(ctx, dir, url, strings.ToUpper(fp), tok)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Customer != "Acme" || cfg.Site != "HQ" || cfg.DeviceID == 0 {
		t.Fatalf("enroll answer: %+v", cfg)
	}
	// The single-use token is now used up.
	if _, err := agent.Enroll(ctx, t.TempDir(), url, fp, tok); err == nil {
		t.Fatal("single-use token enrolled a second device")
	}
	loaded, err := agent.LoadConfig(dir)
	if err != nil || loaded.AgentID != cfg.AgentID {
		t.Fatalf("config not saved: %v", err)
	}

	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	collected := make(chan struct{}, 4)
	a := &agent.Agent{Dir: dir, Cfg: loaded, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Info: func() agent.SysInfo {
			return agent.SysInfo{OS: "Windows 11 Pro 24H2", OSVersion: "10.0", OSBuild: "26100.1", BootTime: time.Now().Add(-time.Hour), LoggedOnUser: `ACME\pera`}
		},
		Collect: func(context.Context) *proto.Inventory {
			collected <- struct{}{}
			return &proto.Inventory{CollectedAt: time.Now(), Hostname: "PC-01", OS: proto.OSInfo{Name: "Microsoft Windows 11 Pro", Build: "26100.1"},
				Disks: []proto.Disk{{Drive: "C:", Size: 100 << 30, Free: 5 << 30}}, Software: []proto.Software{{Name: "7-Zip", Version: "24.08"}}}
		}}
	done := make(chan error, 1)
	go func() { done <- a.Run(runCtx) }()

	var d *store.Device
	waitFor(t, "inventory", func() bool {
		d, _ = e.st.Device(ctx, cfg.DeviceID)
		return d != nil && d.Inventory != nil && d.Connected
	})
	if d.LastUser != `ACME\pera` || d.OS != "Microsoft Windows 11 Pro" || len(d.Inventory.Software) != 1 || !e.srv.Connected(d.ID) {
		t.Fatalf("device after hello+inventory: %+v", d)
	}

	// The console shows it; a technician of another customer does not see it.
	admin, _ := e.setupAdmin("192.168.1.10")
	r := admin.get("/devices")
	if !strings.Contains(r.body, "PC-01") && !strings.Contains(r.body, d.Hostname) {
		t.Fatalf("device list lacks the device: %s", r.body)
	}
	r = admin.get("/devices/" + itoa(d.ID))
	if r.code != http.StatusOK || !strings.Contains(r.body, "7-Zip") || !strings.Contains(r.body, "Online") {
		t.Fatalf("device page: %d", r.code)
	}
	// Refresh inventory reaches the agent.
	<-collected
	if r := admin.post("/devices/" + itoa(d.ID) + "/refresh"); r.code != http.StatusSeeOther {
		t.Fatalf("refresh: %d", r.code)
	}
	select {
	case <-collected:
	case <-time.After(10 * time.Second):
		t.Fatal("inventory request did not reach the agent")
	}

	// Removing the device closes the channel and the key stops working.
	if r := admin.post("/devices/" + itoa(d.ID) + "/delete"); r.code != http.StatusSeeOther {
		t.Fatalf("delete: %d", r.code)
	}
	waitFor(t, "disconnect", func() bool { return !e.srv.Connected(d.ID) })
	if _, err := e.st.Device(ctx, d.ID); err == nil {
		t.Fatal("device still exists")
	}
	stop()
	<-done
}

func TestAgentEndpointRequiresClientCert(t *testing.T) {
	e := newEnv(t)
	url, _ := agentServer(t, e)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // #nosec G402 -- test
	resp, err := c.Post(url+proto.PathEnroll, "application/json", strings.NewReader(`{"protocol":1,"token":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("enroll without client certificate: %d", resp.StatusCode)
	}
	resp, err = c.Get(url + proto.PathConnect)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("connect without client certificate: %d", resp.StatusCode)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// startAgent enrolls and runs an agent against the test server.
func startAgent(t *testing.T, e *env) (*store.Device, context.CancelFunc) {
	t.Helper()
	return startAgentWith(t, e, nil)
}

// startAgentWith runs an agent whose metrics come from metrics (nil: empty).
func startAgentWith(t *testing.T, e *env, metrics func(context.Context) *proto.Metrics) (*store.Device, context.CancelFunc) {
	t.Helper()
	if metrics == nil {
		metrics = func(context.Context) *proto.Metrics { return &proto.Metrics{} }
	}
	agent.ProtectDir = func(string) error { return nil }
	ctx := context.Background()
	cust, _ := e.st.CreateCustomer(ctx, "Files Inc", "")
	site, _ := e.st.CreateSite(ctx, cust, "HQ", "", "")
	tok, _ := e.st.CreateEnrollToken(ctx, site, "", "admin", time.Hour, 1)
	url, fp := agentServer(t, e)
	dir := t.TempDir()
	cfg, err := agent.Enroll(ctx, dir, url, fp, tok)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.CommandKey) != 32 {
		t.Fatal("enrollment did not deliver the command key")
	}
	runCtx, cancel := context.WithCancel(ctx)
	a := &agent.Agent{Dir: dir, Cfg: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Info:    func() agent.SysInfo { return agent.SysInfo{OS: "Windows"} },
		Collect: func(context.Context) *proto.Inventory { return &proto.Inventory{} }, Metrics: metrics}
	done := make(chan struct{})
	go func() { _ = a.Run(runCtx); close(done) }()
	// stop waits for the agent to end, so the test can remove its folder.
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
		}
	}
	waitFor(t, "agent channel", func() bool { return e.srv.Connected(cfg.DeviceID) })
	d, _ := e.st.Device(ctx, cfg.DeviceID)
	return d, stop
}

func TestFileManager(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the console builds Windows paths")
	}
	e := newEnv(t)
	e.useRealClock()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	d, stop := startAgent(t, e)
	defer stop()
	admin, _ := e.setupAdmin("192.168.1.10")
	base := "/devices/" + itoa(d.ID) + "/files"
	work := t.TempDir()
	os.WriteFile(filepath.Join(work, "hello.txt"), []byte("hello from the agent"), 0o600)

	r := admin.get(base)
	if r.code != http.StatusOK || !strings.Contains(r.body, `class="drive"`) {
		t.Fatalf("drives: %d", r.code)
	}
	r = admin.get(base + "?path=" + url.QueryEscape(work))
	if r.code != http.StatusOK || !strings.Contains(r.body, "hello.txt") {
		t.Fatalf("listing: %d %s", r.code, r.body)
	}
	r = admin.get(base + "/download?path=" + url.QueryEscape(filepath.Join(work, "hello.txt")))
	if r.code != http.StatusOK || r.body != "hello from the agent" {
		t.Fatalf("download: %d %q", r.code, r.body)
	}

	// Upload 2.5 MB (three chunks) through a multipart form.
	payload := bytes.Repeat([]byte("0123456789"), 250000)
	var mb bytes.Buffer
	mw := multipart.NewWriter(&mb)
	mw.WriteField("dir", work)
	fw, _ := mw.CreateFormFile("file", "big.bin")
	fw.Write(payload)
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, "http://cz.test"+base+"/upload", &mb)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Origin", "http://cz.test")
	req.RemoteAddr = admin.ip + ":1"
	for k, v := range admin.cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("upload: %d", w.Code)
	}
	got, err := os.ReadFile(filepath.Join(work, "big.bin"))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("uploaded file differs: %v", err)
	}

	if r := admin.post(base+"/mkdir", "dir", work, "name", "New"); r.code != http.StatusSeeOther {
		t.Fatalf("mkdir: %d", r.code)
	}
	// Follow the links the pages render (drive, folder, breadcrumb), as a
	// browser does: they must not be escaped twice.
	follow := func(page, marker string) string {
		t.Helper()
		m := regexp.MustCompile(`href="(` + regexp.QuoteMeta(base) + `\?path=[^"]+)"[^>]*>` + marker).FindStringSubmatch(page)
		if m == nil {
			t.Fatalf("no link to %q", marker)
		}
		r := admin.get(html.UnescapeString(m[1]))
		if r.code != http.StatusOK || strings.Contains(r.body, "not an absolute path") || strings.Contains(r.body, `role="alert"><svg`) && strings.Contains(r.body, "%5C") {
			t.Fatalf("link %s: %d", m[1], r.code)
		}
		return r.body
	}
	follow(admin.get(base).body, `\s*<span class="drive-head">`)
	listing := admin.get(base + "?path=" + url.QueryEscape(work)).body
	sub := follow(listing, `<svg[^>]*>.*?</svg>New</a>`)
	if !strings.Contains(sub, "This folder is empty") {
		t.Fatal("folder link did not open the folder")
	}
	follow(sub, filepath.Base(work)+"</a>") // breadcrumb back to the parent
	if r := admin.post(base+"/mkdir", "dir", work, "name", `..\evil`); r.code != http.StatusSeeOther {
		t.Fatalf("bad name: %d", r.code)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(work), "evil")); err == nil {
		t.Fatal("folder created outside with a traversal name")
	}
	if r := admin.post(base+"/rename", "path", filepath.Join(work, "big.bin"), "name", "renamed.bin"); r.code != http.StatusSeeOther {
		t.Fatalf("rename: %d", r.code)
	}
	if r := admin.post(base+"/delete", "path", filepath.Join(work, "renamed.bin")); r.code != http.StatusSeeOther {
		t.Fatalf("delete: %d", r.code)
	}
	if _, err := os.Stat(filepath.Join(work, "renamed.bin")); err == nil {
		t.Fatal("file not deleted")
	}
	if _, err := os.Stat(filepath.Join(work, "New")); err != nil {
		t.Fatal("folder not created")
	}

	// A read-only user cannot use the file manager.
	admin.post("/users", "username", "viewer", "password", "viewer password 1", "role", "readonly", "all_customers", "1")
	v := e.client("192.168.1.31")
	if r := v.post("/login", "username", "viewer", "password", "viewer password 1"); r.code != http.StatusSeeOther {
		t.Fatalf("viewer sign-in: %d %s", r.code, r.loc)
	}
	sec := secretRE.FindStringSubmatch(v.get("/login/enroll").body)[1]
	if r := v.post("/login/enroll", "code", e.code(sec)); r.code != http.StatusOK || !strings.Contains(r.body, `class="codes"`) {
		t.Fatalf("viewer 2FA enrollment: %d %s %s", r.code, r.loc, r.body)
	}
	if r := v.post("/account/password", "current", "viewer password 1", "password", "viewer password 22", "password2", "viewer password 22"); r.code != http.StatusSeeOther {
		t.Fatalf("viewer password change: %d %s", r.code, r.loc)
	}
	if r := v.get(base + "?path=" + url.QueryEscape(work)); r.code != http.StatusForbidden {
		t.Fatalf("read-only user listed files: %d %s", r.code, r.loc)
	}

	r = admin.get("/audit")
	for _, want := range []string{"file.list", "file.download", "file.upload", "file.mkdir", "file.rename", "file.delete"} {
		if !strings.Contains(r.body, want) {
			t.Errorf("audit lacks %s", want)
		}
	}
	stop()
}

func TestCommandsNeedTheRightKey(t *testing.T) {
	e := newEnv(t)
	e.useRealClock()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	d, stop := startAgent(t, e)
	defer stop()
	// The server's key changes (e.g. a stolen database on another server):
	// the agent refuses its commands.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = other
	err := e.srv.CallForTest(context.Background(), d.ID, proto.KindFSDrives)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("command with a wrong key: %v", err)
	}
	e.srv.CommandKey = key
	if err := e.srv.CallForTest(context.Background(), d.ID, proto.KindFSDrives); err != nil {
		t.Fatalf("command with the right key: %v", err)
	}
}

func TestAlertsEndToEnd(t *testing.T) {
	e := newEnv(t)
	e.useRealClock()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	var free atomic.Uint64
	free.Store(1 << 30) // 1 GB of 100 GB: critical
	d, stop := startAgentWith(t, e, func(context.Context) *proto.Metrics {
		return &proto.Metrics{CPU: 10, MemTotal: 8 << 30, MemUsed: 2 << 30, StoppedAuto: []string{"Spooler"},
			Disks: []proto.Disk{{Drive: "C:", Size: 100 << 30, Free: free.Load()}}}
	})
	defer stop()
	ctx := context.Background()
	// The agent sends the first heartbeat with metrics 10 s after connecting.
	waitForUpTo(t, "first heartbeat with metrics", 25*time.Second, func() bool {
		m, _, _, _ := e.st.DeviceMetrics(ctx, d.ID)
		return m != nil
	})
	admin, _ := e.setupAdmin("192.168.1.10")
	// Chat and webhook channels receive the alerts.
	var hookMu sync.Mutex
	hooks := map[string][]string{}
	sigOK := true
	hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		hookMu.Lock()
		defer hookMu.Unlock()
		hooks[r.URL.Path] = append(hooks[r.URL.Path], string(b))
		if r.URL.Path == "/hook" {
			m := hmac.New(sha256.New, []byte("s3cret"))
			m.Write(b)
			if r.Header.Get("X-RMMZit-Signature") != "sha256="+hex.EncodeToString(m.Sum(nil)) {
				sigOK = false
			}
		}
	}))
	defer hookSrv.Close()
	got := func(path string) []string {
		hookMu.Lock()
		defer hookMu.Unlock()
		return append([]string(nil), hooks[path]...)
	}
	// The customer's policy opens nothing before the channels exist (policy
	// changes check the alerts at once); then its rules are tightened.
	rules := []string{"alerts_set", "1", "cpu_percent", "90", "cpu_minutes", "15", "mem_percent", "90", "mem_minutes", "15", "offline_minutes", "15", "reboot_days", "7"}
	pid := customerPolicy(t, admin, d.CustomerID, append([]string{"name", "Alerts", "disk_percent", "100", "disk_min_free_gb", "0"}, rules...)...)
	time.Sleep(500 * time.Millisecond) // the checks started by the policy changes
	e.srv.CheckAlerts(ctx)
	admin.post("/settings/channels", "action", "add", "name", "Ops hook", "kind", "webhook", "url", hookSrv.URL+"/hook", "secret", "s3cret", "on_resolve", "1")
	admin.post("/settings/channels", "action", "add", "name", "#it", "kind", "slack", "url", hookSrv.URL+"/slack", "critical", "1")
	admin.post("/settings/channels", "action", "add", "name", "Teams", "kind", "teams", "url", hookSrv.URL+"/teams")
	if r := admin.post("/settings/channels", "action", "add", "name", "bad", "kind", "slack", "url", "ftp://x"); r.code != http.StatusSeeOther {
		t.Fatalf("bad channel: %d", r.code)
	}
	if mp := admin.get("/settings/monitoring").body; !strings.Contains(mp, "Ops hook") || strings.Contains(mp, hookSrv.URL) || strings.Contains(mp, "bad</b>") {
		t.Fatal("channels list (URLs must not be shown)")
	}
	if r := admin.post("/policies/"+pid, append([]string{"name", "Alerts", "disk_percent", "90", "disk_min_free_gb", "5", "watch_services", "Spooler"}, rules...)...); r.code != http.StatusSeeOther {
		t.Fatalf("policy: %d", r.code)
	}
	e.srv.CheckAlerts(ctx)
	r := admin.get("/alerts")
	if !strings.Contains(r.body, "Low disk space") {
		t.Fatalf("no alerts opened: %s", regexp.MustCompile(`<td class="detail">[^<]*`).FindAllString(admin.get("/audit").body, 8))
	}
	for i := 0; i < 100 && !(len(got("/hook")) >= 1 && len(got("/slack")) >= 1 && len(got("/teams")) >= 1); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if n := [3]int{len(got("/hook")), len(got("/slack")), len(got("/teams"))}; n != [3]int{1, 1, 1} {
		t.Fatalf("notifications per channel: %v; audit %s", n, regexp.MustCompile(`<td class="detail">[^<]*`).FindAllString(admin.get("/audit").body, 6))
	}
	if h := got("/hook")[0]; !strings.Contains(h, `"event":"alert.opened"`) || !strings.Contains(h, `"title":"Service stopped"`) || !strings.Contains(h, `"title":"Low disk space"`) {
		t.Fatalf("webhook body: %s", h)
	}
	if s := got("/slack")[0]; !strings.Contains(s, `"text"`) || !strings.Contains(s, "Low disk space") {
		t.Fatalf("slack: %s", s)
	}
	if tm := got("/teams")[0]; !strings.Contains(tm, "AdaptiveCard") {
		t.Fatalf("teams body: %s", tm)
	}
	if !strings.Contains(r.body, "Low disk space") || !strings.Contains(r.body, "Service stopped") || !strings.Contains(r.body, `class="navcount">2<`) {
		t.Fatalf("alerts page: %s", r.body)
	}
	if r := admin.get("/devices/" + itoa(d.ID)); !strings.Contains(r.body, "Open alerts") || !strings.Contains(r.body, "Load now") {
		t.Fatal("device page lacks alerts or load")
	}
	list, _ := e.st.Alerts(ctx, &store.User{Role: store.RoleAdmin}, store.AlertFilter{Open: true})
	if r := admin.post("/alerts/"+itoa(list[0].ID)+"/ack", "back", "/alerts"); r.code != http.StatusSeeOther {
		t.Fatalf("ack: %d", r.code)
	}
	if r := admin.get("/alerts"); !strings.Contains(r.body, "seen by admin") || !strings.Contains(r.body, `class="navcount">1<`) {
		t.Fatal("acknowledged alert not shown as seen")
	}
	// The disk gets space: the next heartbeat and check resolve the alert.
	free.Store(50 << 30)
	stop()
	time.Sleep(200 * time.Millisecond)
	_ = e.st.SaveMetrics(ctx, d.ID, &proto.Metrics{Disks: []proto.Disk{{Drive: "C:", Size: 100 << 30, Free: 50 << 30}}, StoppedAuto: []string{}})
	_ = e.st.AgentHeartbeat(ctx, d.ID, proto.Heartbeat{})
	e.st.Pool().Exec(ctx, `UPDATE devices SET connected=true WHERE id=$1`, d.ID)
	e.srv.CheckAlerts(ctx)
	if open, _ := e.st.Alerts(ctx, &store.User{Role: store.RoleAdmin}, store.AlertFilter{Open: true}); len(open) != 0 {
		t.Fatalf("alerts not resolved: %+v", open)
	}
	waitFor(t, "resolved notification", func() bool { return len(got("/hook")) == 2 })
	if h := got("/hook")[1]; !strings.Contains(h, `"event":"alert.resolved"`) {
		t.Fatalf("resolved webhook: %s", h)
	}
	if len(got("/slack")) != 1 {
		t.Fatal("slack got resolved alerts although switched off")
	}
	if !sigOK {
		t.Fatal("webhook signature wrong")
	}
	if mp := admin.get("/settings/monitoring").body; true {
		id := regexp.MustCompile(`name="id" value="([^"]+)">\s*<button class="secondary sm" name="action" value="test">`).FindStringSubmatch(mp)
		if id == nil {
			t.Fatal("no test button")
		}
		admin.post("/settings/channels", "action", "test", "id", id[1])
		waitFor(t, "test notification", func() bool { return len(got("/hook")) == 3 })
		if !strings.Contains(got("/hook")[2], `"event":"test"`) {
			t.Fatal("test notification")
		}
	}
	if r := admin.get("/alerts?all=1"); !strings.Contains(r.body, "Resolved") {
		t.Fatal("resolved alerts not listed")
	}
}

func TestFolderZip(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the console builds Windows paths")
	}
	e := newEnv(t)
	e.useRealClock()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	d, stop := startAgent(t, e)
	defer stop()
	admin, _ := e.setupAdmin("192.168.1.10")
	work := t.TempDir()
	big := bytes.Repeat([]byte("zip me "), 400000) // 2.8 MB, several chunks
	os.MkdirAll(filepath.Join(work, "Docs", "Deep"), 0o700)
	os.WriteFile(filepath.Join(work, "a.txt"), []byte("alpha"), 0o600)
	os.WriteFile(filepath.Join(work, "Docs", "b.txt"), []byte("beta"), 0o600)
	os.WriteFile(filepath.Join(work, "Docs", "Deep", "big.bin"), big, 0o600)
	os.Mkdir(filepath.Join(work, "Empty"), 0o700)

	// The folder's own page links to its ZIP.
	page := admin.get("/devices/" + itoa(d.ID) + "/files?path=" + url.QueryEscape(work)).body
	m := regexp.MustCompile(`href="(/devices/\d+/files/zip\?path=[^"]+)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no ZIP link on the folder page")
	}
	r := admin.get(html.UnescapeString(m[1]))
	if r.code != http.StatusOK {
		t.Fatalf("zip: %d", r.code)
	}
	zr, err := zip.NewReader(bytes.NewReader([]byte(r.body)), int64(len(r.body)))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		got[f.Name] = string(b)
	}
	if got["a.txt"] != "alpha" || got["Docs/b.txt"] != "beta" || got["Docs/Deep/big.bin"] != string(big) {
		t.Fatalf("zip content: %v", len(got))
	}
	if _, ok := got["Empty/"]; !ok {
		t.Fatal("empty folder missing")
	}
	if a := admin.get("/audit").body; !strings.Contains(a, "file.download.folder") {
		t.Fatal("folder download not audited")
	}
}
