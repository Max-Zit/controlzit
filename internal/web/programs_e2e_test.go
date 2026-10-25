//go:build windows

package web_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
)

// The Installed tab lists the programs of the computer from the registry
// (this test computer); a bad program key is refused before the agent.
func TestInstalledPrograms(t *testing.T) {
	e := newEnv(t)
	e.useRealClock()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	d, stop := startAgent(t, e)
	defer stop()
	admin, _ := e.setupAdmin("192.168.1.10")
	base := "/devices/" + itoa(d.ID) + "/software"

	r := admin.get(base + "?view=list")
	if r.code != http.StatusOK || !strings.Contains(r.body, `name="key" value="HKLM`) {
		t.Fatalf("installed programs: %d", r.code)
	}
	if r := admin.get(base + "?view=list&q=zz-no-such-program-zz"); strings.Contains(r.body, `name="key"`) {
		t.Fatal("filter shows programs")
	}
	if r := admin.post(base, "action", "remove", "key", `HKLM64:..\Run`, "view", "list"); r.code != http.StatusSeeOther {
		t.Fatalf("bad key: %d", r.code)
	}
	if strings.Contains(admin.get("/audit?q=software.uninstall").body, "Run") {
		t.Fatal("a bad key reached the agent")
	}
}
