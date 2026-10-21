//go:build !windows

package agent

import (
	"context"
	"os"
	"runtime"
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
