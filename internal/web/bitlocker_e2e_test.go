//go:build windows

package web_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/max-zit/rmmzit/internal/agent"
	"github.com/max-zit/rmmzit/internal/proto"
)

// Recovery keys are collected, stored sealed and shown only after the
// password is confirmed; a policy that requires BitLocker has the agent add
// a recovery key, which the server stores, before the encryption starts.
func TestBitLocker(t *testing.T) {
	e := newEnv(t)
	e.useRealClock()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	ctx := context.Background()

	// A fake BitLocker: D: is encrypted; C: gets a key on prepare and starts
	// encrypting on enable.
	var mu sync.Mutex
	var actions []string
	cKey := ""
	encrypting := false
	agent.BitLocker = func(_ context.Context, action, _ string) (*proto.BitLockerReport, error) {
		mu.Lock()
		defer mu.Unlock()
		actions = append(actions, action)
		if action == proto.BitLockerPrepare {
			cKey = "111111-222222-333333-444444-555555-666666-777777-888888"
		}
		started := action == proto.BitLockerEnable && !encrypting
		if action == proto.BitLockerEnable {
			encrypting = true
		}
		c := proto.BitLockerVolume{Mount: "C:", Type: "OperatingSystem", Protection: "Off", Status: "FullyDecrypted"}
		if cKey != "" {
			c.Keys = []proto.RecoveryKey{{ID: "{C0C0C0C0-0000-0000-0000-000000000001}", Password: cKey}}
		}
		if encrypting {
			c.Status = "EncryptionInProgress"
		}
		d := proto.BitLockerVolume{Mount: "D:", Type: "Data", Protection: "On", Status: "FullyEncrypted",
			Keys: []proto.RecoveryKey{{ID: "{D0D0D0D0-0000-0000-0000-000000000002}", Password: "123456-123456-123456-123456-123456-123456-123456-123456"}}}
		return &proto.BitLockerReport{TPMPresent: true, TPMReady: true, Volumes: []proto.BitLockerVolume{c, d}, Started: started}, nil
	}
	d, stop := startAgent(t, e)
	defer stop()
	admin, _ := e.setupAdmin("192.168.1.10")
	pw := "admin password 123"
	base := "/devices/" + itoa(d.ID) + "/bitlocker"

	// Collect: the D: key is stored, and its value is not on the page.
	if r := admin.post(base + "/collect"); r.code != http.StatusSeeOther {
		t.Fatalf("collect: %d", r.code)
	}
	page := admin.get(base).body
	if !strings.Contains(page, "{D0D0D0D0-0000-0000-0000-000000000002}") || strings.Contains(page, "123456-123456") {
		t.Fatal("key list")
	}
	if strings.Contains(admin.get("/audit?q=bitlocker").body, "123456-123456") {
		t.Fatal("a key reached the audit log")
	}
	// Reveal: wrong password refused, right password shows the key.
	if r := admin.post(base+"/reveal", "protector", "{D0D0D0D0-0000-0000-0000-000000000002}", "password", "wrong"); strings.Contains(r.body, "123456-123456") {
		t.Fatal("key shown with a wrong password")
	}
	r := admin.do(http.MethodPost, base+"/reveal", url.Values{"protector": {"{D0D0D0D0-0000-0000-0000-000000000002}"}, "password": {pw}}, nil)
	if !strings.Contains(r.body, "123456-123456-123456-123456-123456-123456-123456-123456") {
		t.Fatalf("reveal: %d", r.code)
	}
	if a := admin.get("/audit?q=bitlocker.reveal").body; !strings.Contains(a, "showed the BitLocker recovery key") || !strings.Contains(a, "refused") {
		t.Fatal("audit of reveals")
	}

	// A policy requires BitLocker; the inventory shows C: decrypted.
	r = admin.do(http.MethodPost, "/policies/new", url.Values{"name": {"Encrypt"}, "bitlocker_set": {"1"}, "bitlocker_require": {"1"}}, nil)
	pid := strings.TrimPrefix(r.loc, "/policies/")
	admin.post("/policies/"+pid+"/assign", "target", "device:"+itoa(d.ID))
	if err := e.st.SaveInventory(ctx, d.ID, &proto.Inventory{BitLocker: []proto.BitLocker{{Drive: "C:", Protection: "off", Status: "fully decrypted"}}}); err != nil {
		t.Fatal(err)
	}
	e.srv.RunBitLocker(ctx)
	e.srv.RunBitLocker(ctx)
	waitForUpTo(t, "BitLocker switched on", 30*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return encrypting
	})
	mu.Lock()
	got := strings.Join(actions, ",")
	mu.Unlock()
	if !strings.HasSuffix(got, "prepare,enable") || strings.Count(got, "enable") != 1 {
		t.Fatalf("actions: %s", got)
	}
	if !strings.Contains(admin.get(base).body, "{C0C0C0C0-0000-0000-0000-000000000001}") {
		t.Fatal("the C: key was not stored")
	}
	waitFor(t, "task result", func() bool {
		return strings.Contains(admin.get("/devices/"+itoa(d.ID)+"/activity").body, "the recovery key is stored")
	})
}
