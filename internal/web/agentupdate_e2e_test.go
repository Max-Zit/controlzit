package web_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/max-zit/controlzit/internal/agent"
)

func uploadPackage(t *testing.T, e *env, c *client, name string, body []byte) resp {
	t.Helper()
	var mb bytes.Buffer
	mw := multipart.NewWriter(&mb)
	fw, _ := mw.CreateFormFile("file", name)
	fw.Write(body)
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, "http://cz.test/settings/agents/package", &mb)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Origin", "http://cz.test")
	req.RemoteAddr = c.ip + ":1"
	for k, v := range c.cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return resp{code: w.Code, loc: w.Header().Get("Location"), body: w.Body.String()}
}

func TestAgentSelfUpdate(t *testing.T) {
	e := newEnv(t)
	e.now = time.Now()
	e.srv.SetClock(time.Now)
	e.st.SetClock(time.Now)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	e.srv.DownloadsDir = t.TempDir()
	var mu sync.Mutex
	var installed []byte
	agent.RunInstaller = func(path, _ string) error {
		b, err := os.ReadFile(path)
		mu.Lock()
		installed = b
		mu.Unlock()
		return err
	}
	d, stop := startAgent(t, e)
	defer stop()
	admin, _ := e.setupAdmin("192.168.1.10")

	if r := admin.get("/settings/agents"); r.code != http.StatusOK || !strings.Contains(r.body, "No installer with a known version") {
		t.Fatalf("settings page without a package: %d", r.code)
	}
	// Only Windows Installer files are accepted.
	uploadPackage(t, e, admin, "controlzit-agent-9.9.9-x64.msi", []byte("MZ not an msi at all"))
	if _, err := os.Stat(e.srv.DownloadsDir + "/controlzit-agent-x64.msi"); err == nil {
		t.Fatal("a non-MSI file was accepted")
	}
	msi := append([]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), bytes.Repeat([]byte("installer"), 50000)...)
	if r := uploadPackage(t, e, admin, "controlzit-agent-9.9.9-x64.msi", msi); r.code != http.StatusSeeOther {
		t.Fatalf("upload: %d", r.code)
	}
	sum := sha256.Sum256(msi)
	r := admin.get("/settings/agents")
	if !strings.Contains(r.body, "9.9.9") || !strings.Contains(r.body, hexs(sum[:])) || !strings.Contains(r.body, "1 agents run an older version") {
		t.Fatalf("settings page after the upload: %s", r.body)
	}
	if r := admin.get("/devices/" + itoa(d.ID)); !strings.Contains(r.body, "version 9.9.9 is available") {
		t.Fatal("device page does not offer the update")
	}

	// The agent downloads the installer, checks the hash and starts it.
	if r := admin.post("/devices/" + itoa(d.ID) + "/agent-update"); r.code != http.StatusSeeOther {
		t.Fatalf("update: %d", r.code)
	}
	mu.Lock()
	got := installed
	mu.Unlock()
	if !bytes.Equal(got, msi) {
		t.Fatalf("the agent installed %d bytes, want the uploaded %d", len(got), len(msi))
	}
	if !strings.Contains(admin.get("/audit?q=agent.update").body, "to 9.9.9 started") {
		t.Fatal("update not audited")
	}

	// A Linux agent is uploaded next to the MSI.
	elf := make([]byte, 4096)
	copy(elf, "\x7fELF")
	elf[4], elf[5], elf[18] = 2, 1, 0x3e
	if r := uploadPackage(t, e, admin, "controlzit-agent-9.9.9-linux-amd64", elf); r.code != http.StatusSeeOther {
		t.Fatalf("linux upload: %d", r.code)
	}
	if r := admin.get("/settings/agents"); !strings.Contains(r.body, "Linux x86-64") || !strings.Contains(r.body, "Windows (MSI)") {
		t.Fatal("both installers should be listed")
	}

	// The package endpoint needs an agent identity.
	if r := e.client("10.0.0.9").get("/agent/v1/package"); r.code == http.StatusOK {
		t.Fatal("package served on the console without an agent certificate")
	}

	// Read-only users cannot trigger updates or see the settings.
	admin.post("/users", "username", "viewer", "password", "viewer password 1", "role", "readonly", "all_customers", "1")
	v := e.client("192.168.1.31")
	v.post("/login", "username", "viewer", "password", "viewer password 1")
	sec := secretRE.FindStringSubmatch(v.get("/login/enroll").body)[1]
	v.post("/login/enroll", "code", e.code(sec))
	v.post("/account/password", "current", "viewer password 1", "password", "viewer password 22", "password2", "viewer password 22")
	if r := v.post("/devices/" + itoa(d.ID) + "/agent-update"); r.code != http.StatusForbidden {
		t.Errorf("read-only user updated the agent: %d", r.code)
	}
	if r := v.get("/settings/agents"); r.code != http.StatusForbidden {
		t.Errorf("read-only user opened agent updates: %d", r.code)
	}
}

func hexs(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, digits[x>>4], digits[x&15])
	}
	return string(out)
}
