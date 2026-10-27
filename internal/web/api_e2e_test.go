package web_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

var tokenRE = regexp.MustCompile(`czt_[A-Za-z0-9_-]{40,}`)

// apiCall sends an API request with a bearer token (no cookies).
func apiCall(e *env, token, method, path, body string) (int, string) {
	req := httptest.NewRequest(method, "http://cz.test"+path, strings.NewReader(body))
	req.RemoteAddr = "192.168.1.20:5000"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// Tokens act with their role and the user's customers; changes are
// audited; a deleted token and a browser session do not work.
func TestAPI(t *testing.T) {
	e := newEnv(t)
	e.useRealClock()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	d, stop := startAgent(t, e)
	defer stop()
	admin, _ := e.setupAdmin("192.168.1.10")

	newToken := func(role string) string {
		t.Helper()
		r := admin.post("/account/tokens", "name", "tool "+role, "role", role, "days", "30")
		tok := tokenRE.FindString(r.body)
		if r.code != http.StatusOK || tok == "" {
			t.Fatalf("token %s: %d", role, r.code)
		}
		return tok
	}
	ro, rw := newToken("readonly"), newToken("admin")
	if strings.Contains(admin.get("/account").body, ro) {
		t.Fatal("the token is shown again")
	}

	if c, _ := apiCall(e, "", "GET", "/api/v1/me", ""); c != http.StatusUnauthorized {
		t.Fatalf("no token: %d", c)
	}
	if c, _ := apiCall(e, "czt_wrong", "GET", "/api/v1/me", ""); c != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", c)
	}
	// A browser session is not an API credential.
	req := httptest.NewRequest("GET", "http://cz.test/api/v1/me", nil)
	req.RemoteAddr = "192.168.1.10:1"
	for k, v := range admin.cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("session cookie: %d", w.Code)
	}

	c, body := apiCall(e, ro, "GET", "/api/v1/me", "")
	if c != http.StatusOK || !strings.Contains(body, `"role": "readonly"`) {
		t.Fatalf("me: %d %s", c, body)
	}
	c, body = apiCall(e, ro, "GET", "/api/v1/devices", "")
	if c != http.StatusOK || !strings.Contains(body, `"id": `+itoa(d.ID)) {
		t.Fatalf("devices: %d %s", c, body)
	}
	if c, _ := apiCall(e, ro, "POST", "/api/v1/devices/"+itoa(d.ID)+"/tasks", `{"kind":"patch.scan"}`); c != http.StatusForbidden {
		t.Fatalf("read-only token started a task: %d", c)
	}
	if c, _ := apiCall(e, rw, "POST", "/api/v1/devices/"+itoa(d.ID)+"/tasks", `{"kind":"format-disk"}`); c != http.StatusBadRequest {
		t.Fatalf("unknown kind: %d", c)
	}
	if c, _ := apiCall(e, rw, "POST", "/api/v1/devices/"+itoa(d.ID)+"/tasks", `{"kind":"script","shell":"cmd","script":"echo x","extra":1}`); c != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", c)
	}

	// A script through the API, followed until it ends.
	shell, script := "cmd", "echo api-ok"
	if runtime.GOOS != "windows" {
		shell, script = "sh", "echo api-ok"
	}
	c, body = apiCall(e, rw, "POST", "/api/v1/devices/"+itoa(d.ID)+"/tasks", `{"kind":"script","shell":"`+shell+`","script":"`+script+`","timeout":60}`)
	if c != http.StatusAccepted {
		t.Fatalf("task: %d %s", c, body)
	}
	var task struct {
		ID     int64  `json:"id"`
		Status string `json:"status"`
		Result string `json:"result"`
	}
	_ = json.Unmarshal([]byte(body), &task)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && task.Status != "done" && task.Status != "failed" {
		time.Sleep(200 * time.Millisecond)
		_, body = apiCall(e, ro, "GET", "/api/v1/tasks/"+itoa(task.ID), "")
		_ = json.Unmarshal([]byte(body), &task)
	}
	if task.Status != "done" || task.Result != "exit code 0" {
		t.Fatalf("task ended %s: %s", task.Status, task.Result)
	}
	if !strings.Contains(admin.get("/audit?q=task.queue").body, "API token") {
		t.Fatal("audit names the token")
	}
	if c, _ := apiCall(e, rw, "POST", "/api/v1/tasks/"+itoa(task.ID)+"/cancel", ""); c != http.StatusConflict {
		t.Fatalf("cancel an ended task: %d", c)
	}

	// Deleting the token ends its access.
	page := admin.get("/account").body
	id := regexp.MustCompile(`/account/tokens/(\d+)/delete`).FindStringSubmatch(page)
	if id == nil {
		t.Fatal("no delete button")
	}
	admin.post("/account/tokens/" + id[1] + "/delete")
	if c, _ := apiCall(e, ro, "GET", "/api/v1/me", ""); c != http.StatusUnauthorized {
		t.Fatalf("deleted token still works: %d", c)
	}
}
