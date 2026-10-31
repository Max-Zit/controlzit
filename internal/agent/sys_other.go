//go:build !windows && !linux

package agent

import (
	"context"
	"errors"
	"os"
	"runtime"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
)

func basicInfo() SysInfo { return SysInfo{OS: BasicOS()} }

// CollectInventory is minimal on systems without a full agent.
func CollectInventory(ctx context.Context) *proto.Inventory {
	host, _ := os.Hostname()
	return &proto.Inventory{CollectedAt: time.Now().UTC(), Hostname: host, OS: proto.OSInfo{Name: runtime.GOOS, Arch: runtime.GOARCH}}
}

// CollectMetrics is not implemented on this system.
func CollectMetrics(ctx context.Context) *proto.Metrics { return &proto.Metrics{} }

func startHelper(string, proto.RDStart) error {
	return errors.New("remote desktop is not available on this system")
}
