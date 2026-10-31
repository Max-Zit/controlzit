package web

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRenameLegacyBackups(t *testing.T) {
	s := &Server{DataDir: t.TempDir()}
	dir := s.backupDir()
	_ = os.MkdirAll(dir, 0o700)
	for _, n := range []string{"controlzit-backup-20261030-120000.czb", "controlzit-backup-20261030-130000.czb.part", "other.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s.renameLegacyBackupFiles()
	for n, want := range map[string]bool{"rmmzit-backup-20261030-120000.rzb": true, "controlzit-backup-20261030-120000.czb": false, "other.txt": true} {
		if _, err := os.Stat(filepath.Join(dir, n)); (err == nil) != want {
			t.Errorf("%s exists=%v", n, err == nil)
		}
	}
	if got := s.localBackups(); len(got) != 1 || got[0].Name != "rmmzit-backup-20261030-120000.rzb" {
		t.Errorf("list %+v", got)
	}
}
