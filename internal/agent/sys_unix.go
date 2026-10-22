//go:build !windows

package agent

import (
	"errors"
	"os"
	"strings"

	"github.com/max-zit/controlzit/internal/proto"
)

func protectDir(dir string) error { return os.Chmod(dir, 0o700) } // #nosec G302 -- a directory needs the x bit; root only

func markEnrolled(bool) {}

const isWindows = false

func hidden(fi os.FileInfo) bool { return strings.HasPrefix(fi.Name(), ".") }

func systemFolders() []string {
	return []string{"/bin", "/boot", "/etc", "/lib", "/lib64", "/sbin", "/usr", "/var", "/proc", "/sys", "/dev", "/run"}
}

func drives() ([]proto.FSDrive, error) { return []proto.FSDrive{{Path: "/", Type: "fixed"}}, nil }

func startHelper(string, proto.RDStart) error {
	return errors.New("remote desktop is not available on this system")
}

func isLink(fi os.FileInfo) bool { return fi.Mode()&os.ModeSymlink != 0 }

func publicStatusDir() string { return "" }

// StartTray does nothing outside Windows.
func StartTray() error { return nil }
