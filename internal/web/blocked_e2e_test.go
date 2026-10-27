//go:build windows

package web_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/max-zit/controlzit/internal/agent"
	"github.com/max-zit/controlzit/internal/proto"
)

// A blocked program in a device's inventory opens an alert; marked for
// removal it is uninstalled silently (a program without a silent uninstall
// is only reported), once until the retry time.
func TestBlockedPrograms(t *testing.T) {
	e := newEnv(t)
	e.useRealClock()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e.srv.CommandKey = key
	var mu sync.Mutex
	var removed []string
	progs := []proto.Program{
		{Key: "HKLM64:{TORRENT}", Name: "uTorrent", Version: "3.6", Silent: true},
		{Key: "HKLM64:{TORRENTWEB}", Name: "uTorrent Web", Version: "1.4"},
		{Key: "HKLM64:{7ZIP}", Name: "7-Zip 24.08", Silent: true},
	}
	oldList := agent.SetHandler(proto.KindPrograms, func(context.Context, json.RawMessage) (any, error) {
		return proto.ProgramsResult{Programs: progs}, nil
	})
	defer func() { agent.SetHandler(proto.KindPrograms, oldList) }()
	oldUn := agent.SetHandler(proto.KindUninstall, func(_ context.Context, raw json.RawMessage) (any, error) {
		var u proto.Uninstall
		_ = json.Unmarshal(raw, &u)
		mu.Lock()
		removed = append(removed, u.Key)
		mu.Unlock()
		return proto.UninstallResult{Name: u.Key, Method: "quiet"}, nil
	})
	defer func() { agent.SetHandler(proto.KindUninstall, oldUn) }()
	d, stop := startAgent(t, e)
	defer stop()
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()
	// After the agent's own (empty) inventory, the test's.
	waitFor(t, "first inventory", func() bool { x, err := e.st.Device(ctx, d.ID); return err == nil && x.Inventory != nil })
	if err := e.st.SaveInventory(ctx, d.ID, &proto.Inventory{Hostname: d.Hostname, OS: proto.OSInfo{Name: "Microsoft Windows 11 Pro"},
		Software: []proto.Software{{Name: "uTorrent", Version: "3.6"}, {Name: "uTorrent Web", Version: "1.4"}, {Name: "7-Zip 24.08"}}}); err != nil {
		t.Fatal(err)
	}
	if r := admin.post("/policies/new", "name", "Bad", "software_set", "1", "blk_match", "ab", "blk_action", "alert"); r.code != http.StatusBadRequest || !strings.Contains(r.body, "3–100 characters") || !strings.Contains(r.body, `value="ab"`) {
		t.Fatal("a blocked name of 2 characters was accepted")
	}
	customerPolicy(t, admin, d.CustomerID, "name", "No torrents", "software_set", "1",
		"blk_match", "torrent", "blk_action", "remove", "blk_match", "", "blk_action", "alert")

	e.srv.CheckAlerts(ctx)
	if b := admin.get("/alerts").body; !strings.Contains(b, "Blocked program installed") || !strings.Contains(b, "uTorrent Web 1.4") {
		t.Fatal("no alert for the blocked program")
	}
	if b := admin.get("/devices/" + itoa(d.ID) + "/policy").body; !strings.Contains(b, "„torrent“") || !strings.Contains(b, "uTorrent 3.6") {
		t.Fatal("device policy page")
	}
	e.srv.RunRequiredSoftware(ctx)
	waitFor(t, "removal", func() bool {
		return strings.Contains(admin.get("/devices/"+itoa(d.ID)+"/activity").body, "1 removed, 0 failed, 1 cannot be removed silently")
	})
	e.srv.RunRequiredSoftware(ctx) // not again before the retry time
	mu.Lock()
	defer mu.Unlock()
	if len(removed) != 1 || removed[0] != "HKLM64:{TORRENT}" {
		t.Fatalf("removed %v", removed)
	}
}
