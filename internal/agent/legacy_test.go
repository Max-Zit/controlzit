package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyDir(t *testing.T) {
	src, dst := t.TempDir(), filepath.Join(t.TempDir(), "new")
	_ = os.MkdirAll(filepath.Join(src, "updates"), 0o700)
	for _, f := range []string{configFile, keyFile, filepath.Join("updates", "x.msi")} {
		if err := os.WriteFile(filepath.Join(src, f), []byte(f), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := copyDir(src, dst); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{configFile, keyFile, filepath.Join("updates", "x.msi")} {
		if b, err := os.ReadFile(filepath.Join(dst, f)); err != nil || string(b) != f {
			t.Errorf("%s: %q %v", f, b, err)
		}
	}
}
