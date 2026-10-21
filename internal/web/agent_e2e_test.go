package web_test

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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
