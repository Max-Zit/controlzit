package web_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/max-zit/controlzit/internal/agent"
	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
	"github.com/max-zit/controlzit/internal/tlsutil"
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
	for i := 0; i < 100; i++ {
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
	e.now = time.Now()
	e.srv.SetClock(time.Now)
	e.st.SetClock(time.Now)
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
	runCtx, stop := context.WithCancel(ctx)
	a := &agent.Agent{Dir: dir, Cfg: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Info:    func() agent.SysInfo { return agent.SysInfo{OS: "Windows"} },
		Collect: func(context.Context) *proto.Inventory { return &proto.Inventory{} }, Metrics: metrics}
	go a.Run(runCtx)
	waitFor(t, "agent channel", func() bool { return e.srv.Connected(cfg.DeviceID) })
	d, _ := e.st.Device(ctx, cfg.DeviceID)
	return d, stop
}

func TestFileManager(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the console builds Windows paths")
	}
	e := newEnv(t)
	e.now = time.Now()
	e.srv.SetClock(time.Now)
	e.st.SetClock(time.Now)
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
	v.post("/login", "username", "viewer", "password", "viewer password 1")
	sec := secretRE.FindStringSubmatch(v.get("/login/enroll").body)[1]
	v.post("/login/enroll", "code", e.code(sec))
	v.post("/account/password", "current", "viewer password 1", "password", "viewer password 22", "password2", "viewer password 22")
	if r := v.get(base + "?path=" + url.QueryEscape(work)); r.code != http.StatusForbidden {
		t.Fatalf("read-only user listed files: %d", r.code)
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
	e.now = time.Now()
	e.srv.SetClock(time.Now)
	e.st.SetClock(time.Now)
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
	e.now = time.Now()
	e.srv.SetClock(time.Now)
	e.st.SetClock(time.Now)
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
	waitFor(t, "first heartbeat with metrics", func() bool {
		m, _, _, _ := e.st.DeviceMetrics(ctx, d.ID)
		return m != nil
	})
	admin, _ := e.setupAdmin("192.168.1.10")
	if r := admin.post("/settings/monitoring", "cpu_percent", "90", "cpu_minutes", "15", "mem_percent", "90", "mem_minutes", "15", "disk_percent", "90",
		"disk_min_free_gb", "5", "offline_minutes", "15", "reboot_days", "7", "watch_services", "Spooler"); r.code != http.StatusSeeOther {
		t.Fatalf("save monitoring: %d %s", r.code, r.body)
	}
	e.srv.CheckAlerts(ctx)
	r := admin.get("/alerts")
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
	if r := admin.get("/alerts?all=1"); !strings.Contains(r.body, "Resolved") {
		t.Fatal("resolved alerts not listed")
	}
}
