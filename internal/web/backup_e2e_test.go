package web_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/rmmzit/internal/backup"
	"github.com/max-zit/rmmzit/internal/store"
	"github.com/max-zit/rmmzit/internal/testdb"
)

// Console backups: the daily schedule, an encrypted file to download, the
// number kept, and a restore of the file into an empty database.
func TestConsoleBackup(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	e.srv.DataDir = dir
	_ = os.MkdirAll(filepath.Join(dir, "tls"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "tls", "agent.key"), []byte("AGENT KEY"), 0o600)
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()
	if _, err := e.st.CreateCustomer(ctx, "Backed Up Ltd", ""); err != nil {
		t.Fatal(err)
	}
	const pass = "a long backup passphrase"
	hour := itoa(int64(e.now.Local().Hour()))
	if r := admin.post("/settings/backup", "enabled", "1", "hour", hour, "keep", "2", "passphrase", "short", "passphrase2", "short"); !strings.Contains(admin.get(r.loc).body, "at least 12 characters") {
		t.Fatal("short passphrase accepted")
	}
	admin.post("/settings/backup", "enabled", "1", "hour", hour, "keep", "2", "passphrase", pass, "passphrase2", pass)

	names := regexp.MustCompile(`rmmzit-backup-\d{8}-\d{6}\.rzb`)
	backups := func() []string {
		return uniq(names.FindAllString(admin.get("/settings/backup").body, -1))
	}
	e.srv.RunBackups(ctx) // the scheduled hour
	waitFor(t, "the scheduled backup", func() bool { return len(backups()) == 1 })
	e.srv.RunBackups(ctx) // once a day
	time.Sleep(300 * time.Millisecond)
	for i := 0; i < 2; i++ {
		e.now = e.now.Add(time.Second)
		admin.post("/settings/backup/run")
		want := min(i+2, 2)
		waitFor(t, "a manual backup", func() bool {
			b := admin.get("/settings/backup").body
			return !strings.Contains(b, "A backup is running") && len(backups()) == want && strings.Contains(b, e.now.Local().Format("20060102-150405"))
		})
	}
	list := backups()
	if len(list) != 2 {
		t.Fatalf("kept %v", list)
	}
	r := admin.get("/settings/backup/file/" + list[0])
	if r.code != 200 || bytes.Contains([]byte(r.body), []byte("AGENT KEY")) {
		t.Fatalf("download %d, encrypted %v", r.code, !strings.Contains(r.body, "AGENT KEY"))
	}
	if admin.get("/settings/backup/file/..%2Fsecret.key").code != 404 {
		t.Fatal("a name outside the list was served")
	}
	if _, err := backup.Inspect(strings.NewReader(r.body), "wrong passphrase"); !errors.Is(err, backup.ErrPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}

	url := testdb.URL(t)
	dst := t.TempDir()
	m, err := backup.Restore(ctx, strings.NewReader(r.body), pass, dst, func(ctx context.Context, rd io.Reader) error {
		return store.RestoreDump(ctx, url, rd)
	})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "tls", "agent.key")); string(b) != "AGENT KEY" || len(m.Files) != 1 {
		t.Fatalf("files %v", m.Files)
	}
	st, err := store.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cs, err := st.AllCustomers(ctx)
	if err != nil || len(cs) != 1 || cs[0].Name != "Backed Up Ltd" {
		t.Fatalf("customers after restore: %+v %v", cs, err)
	}

	admin.post("/settings/backup/delete", "name", list[1])
	if got := backups(); len(got) != 1 {
		t.Fatalf("after delete %v", got)
	}
	if b := admin.get("/audit").body; !strings.Contains(b, "backup.download") || !strings.Contains(b, "backup.create") {
		t.Fatal("backups not audited")
	}
}

func uniq(list []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range list {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
