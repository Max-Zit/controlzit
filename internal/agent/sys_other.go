//go:build !windows

package agent

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
)

func protectDir(dir string) error { return os.Chmod(dir, 0o700) }

func basicInfo() SysInfo { return SysInfo{OS: BasicOS()} }

// CollectInventory is minimal outside Windows (the Linux agent comes later).
func CollectInventory(ctx context.Context) *proto.Inventory {
	host, _ := os.Hostname()
	return &proto.Inventory{CollectedAt: time.Now().UTC(), Hostname: host, OS: proto.OSInfo{Name: runtime.GOOS, Arch: runtime.GOARCH}}
}

func markEnrolled(bool) {}

const isWindows = false

func hidden(fi os.FileInfo) bool { return strings.HasPrefix(fi.Name(), ".") }

func systemFolders() []string {
	return []string{"/bin", "/boot", "/etc", "/lib", "/usr", "/var", "/proc", "/sys", "/dev"}
}

func drives() ([]proto.FSDrive, error) { return []proto.FSDrive{{Path: "/", Type: "fixed"}}, nil }

func startHelper(string, proto.RDStart) error {
	return errors.New("remote desktop is not supported on this system yet")
}

// CollectMetrics is not implemented outside Windows yet.
func CollectMetrics(ctx context.Context) *proto.Metrics { return &proto.Metrics{} }

func isLink(fi os.FileInfo) bool { return fi.Mode()&os.ModeSymlink != 0 }
