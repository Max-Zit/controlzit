//go:build windows

package web_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func uploadSoftware(t *testing.T, e *env, c *client, file string, body []byte, fields ...string) resp {
	t.Helper()
	var mb bytes.Buffer
	mw := multipart.NewWriter(&mb)
	for i := 0; i+1 < len(fields); i += 2 {
		_ = mw.WriteField(fields[i], fields[i+1])
	}
	fw, _ := mw.CreateFormFile("file", file)
	_, _ = fw.Write(body)
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "http://cz.test/software/new", &mb)
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

// A package of the library is uploaded, installed on a device as a job
// (the agent downloads it from the agent endpoint and checks the signed
// hash) and judged by its exit code. cmd.exe stands in for an installer.
func TestSoftwareLibrary(t *testing.T) {
	e := newEnv(t)
	e.useRealClock()
	e.srv.DataDir = t.TempDir()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	d, stop := startAgent(t, e)
	defer stop()
	admin, _ := e.setupAdmin("192.168.1.10")

	if r := uploadSoftware(t, e, admin, "notes.txt", []byte("hello"), "name", "Bad"); !strings.Contains(r.loc, "/software/new") {
		t.Fatalf("a text file was accepted: %d %s", r.code, r.loc)
	}
	exe, err := os.ReadFile(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"))
	if err != nil {
		t.Skip("no cmd.exe:", err)
	}
	if r := uploadSoftware(t, e, admin, "cmd.exe", exe, "name", "Test tool"); !strings.Contains(r.loc, "/software/new") {
		t.Fatal("an EXE without silent arguments was accepted")
	}
	r := uploadSoftware(t, e, admin, `C:\x\cmd tool.exe`, exe, "name", "Test tool", "version", "1.0", "args", "/c exit 0")
	pid := regexp.MustCompile(`^/software/(\d+)$`).FindStringSubmatch(r.loc)
	if r.code != http.StatusSeeOther || pid == nil {
		t.Fatalf("upload: %d %s", r.code, r.loc)
	}
	base := "/software/" + pid[1]
	if b := admin.get(base).body; !strings.Contains(b, "cmd tool.exe") || !strings.Contains(b, "/c exit 0") {
		t.Fatal("package page")
	}
	// Agents fetch only with their certificate.
	if r := e.client("10.0.0.9").get("/agent/v1/library?sha256=00"); r.code == http.StatusOK {
		t.Fatal("library file without a client certificate")
	}

	install := func(want string) string {
		t.Helper()
		r := admin.post(base+"/run", "device", itoa(d.ID))
		if !strings.HasPrefix(r.loc, "/jobs/") {
			t.Fatalf("run: %d %s", r.code, r.loc)
		}
		waitForUpTo(t, "job "+want, 60*time.Second, func() bool {
			b := admin.get(r.loc).body
			return !strings.Contains(b, "data-autorefresh") && strings.Contains(b, want)
		})
		return r.loc
	}
	job := install(">1</b><span>succeeded")
	if b := admin.get(job).body; !strings.Contains(b, "exit code 0") {
		t.Fatal("job result")
	}
	// Exit code 5 is no success.
	if r := admin.post(base, "name", "Test tool", "version", "1.0", "args", "/c exit 5", "codes", "0"); r.code != http.StatusSeeOther {
		t.Fatalf("save: %d", r.code)
	}
	install(">1</b><span>failed")
	if b := admin.get("/audit?q=package.install").body; !strings.Contains(b, "exit code 5") {
		t.Fatal("audit of the installation")
	}
	// Deleting the package removes its file.
	if r := admin.post(base + "/delete"); r.code != http.StatusSeeOther {
		t.Fatalf("delete: %d", r.code)
	}
	if left, _ := filepath.Glob(filepath.Join(e.srv.DataDir, "library", "*")); len(left) != 0 {
		t.Fatalf("files left: %v", left)
	}
}
