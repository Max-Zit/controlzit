package web_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
)

func TestReports(t *testing.T) {
	e := newEnv(t)
	e.useRealClock()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	d, stop := startAgent(t, e)
	defer stop()
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()
	other, _ := e.st.CreateCustomer(ctx, "Other Ltd", "")

	r := admin.get("/reports")
	if r.code != http.StatusOK || !strings.Contains(r.body, "Files Inc") || !strings.Contains(r.body, "All customers") {
		t.Fatalf("reports page: %d", r.code)
	}
	r = admin.get("/reports/view?customer=" + itoa(d.CustomerID) + "&days=7")
	if r.code != http.StatusOK || !strings.Contains(r.body, "Report for the last 7 days") || !strings.Contains(r.body, d.Hostname) || !strings.Contains(r.body, "data-print") {
		t.Fatalf("report: %d %s", r.code, r.body)
	}
	if strings.Contains(r.body, "class=\"sidebar") {
		t.Error("the printable report should not have the console navigation")
	}
	if r := admin.get("/reports/view?customer=0&days=30"); r.code != http.StatusOK || !strings.Contains(r.body, "All customers") {
		t.Fatalf("all customers: %d", r.code)
	}
	if r := admin.get("/reports/view?customer=999999"); r.code != http.StatusNotFound {
		t.Errorf("unknown customer: %d", r.code)
	}

	// Email settings: per-customer recipients, validated addresses.
	if r := admin.post("/settings/reports", "mode", "weekly", "weekday", "1", "monthday", "1", "hour", "7", "language", "sr",
		"copy", "boss@example.com", "to_"+itoa(d.CustomerID), "it@files.example, admin@files.example"); r.code != http.StatusSeeOther {
		t.Fatalf("save: %d", r.code)
	}
	r = admin.get("/settings/reports")
	if !strings.Contains(r.body, `value="it@files.example, admin@files.example"`) || !strings.Contains(r.body, `value="weekly" selected`) {
		t.Fatal("report settings not saved")
	}
	admin.post("/settings/reports", "mode", "weekly", "weekday", "1", "hour", "7", "to_"+itoa(other), "not an address")
	if !strings.Contains(admin.get("/settings/reports").body, "is not an email address") {
		t.Fatal("bad address accepted")
	}
	// Without email set up, sending says so.
	admin.post("/settings/reports/send", "customer", itoa(d.CustomerID))
	if !strings.Contains(admin.get("/settings/reports").body, "email is not set up") {
		t.Fatal("send without email setup")
	}

	// A technician of another customer sees only that customer's report.
	admin.post("/users", "username", "tech", "password", "tech password 123", "role", "technician", "customers", itoa(other))
	tc := e.client("192.168.1.40")
	tc.post("/login", "username", "tech", "password", "tech password 123")
	sec := secretRE.FindStringSubmatch(tc.get("/login/enroll").body)[1]
	tc.post("/login/enroll", "code", e.code(sec))
	tc.post("/account/password", "current", "tech password 123", "password", "tech password 1234", "password2", "tech password 1234")
	if r := tc.get("/reports/view?customer=" + itoa(d.CustomerID)); r.code != http.StatusNotFound {
		t.Errorf("technician saw another customer's report: %d", r.code)
	}
	if r := tc.get("/reports/view?customer=0"); r.code != http.StatusForbidden {
		t.Errorf("technician saw all customers: %d", r.code)
	}
	if r := tc.get("/reports/view?customer=" + itoa(other)); r.code != http.StatusOK || strings.Contains(r.body, d.Hostname) {
		t.Errorf("technician's own customer report: %d", r.code)
	}
	if r := tc.get("/settings/reports"); r.code != http.StatusForbidden {
		t.Errorf("technician opened report settings: %d", r.code)
	}
}
