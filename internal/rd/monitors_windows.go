//go:build windows

package rd

import (
	"sort"
	"syscall"
	"unsafe"

	"github.com/max-zit/controlzit/internal/proto"
)

var (
	pEnumDisplayMonitors = user32.NewProc("EnumDisplayMonitors")
	pGetMonitorInfo      = user32.NewProc("GetMonitorInfoW")
)

type monitorInfo struct {
	Size    uint32
	Monitor rect
	Work    rect
	Flags   uint32
}

const monitorInfoPrimary = 1

var (
	monitorsFound []proto.RDMonitor
	enumCallback  = syscall.NewCallback(func(h, _ uintptr, _ uintptr, _ uintptr) uintptr {
		mi := monitorInfo{}
		mi.Size = uint32(unsafe.Sizeof(mi))
		if r, _, _ := pGetMonitorInfo.Call(h, uintptr(unsafe.Pointer(&mi))); r != 0 { // #nosec G103 -- Win32 struct
			monitorsFound = append(monitorsFound, proto.RDMonitor{X: int(mi.Monitor.Left), Y: int(mi.Monitor.Top),
				W: int(mi.Monitor.Right - mi.Monitor.Left), H: int(mi.Monitor.Bottom - mi.Monitor.Top), Primary: mi.Flags&monitorInfoPrimary != 0})
		}
		return 1
	})
)

// Monitors lists the displays of the attached desktop in virtual-screen
// pixels, the primary one first, then left to right. Call it from the
// desktop thread only (the callback collects into a package variable).
func Monitors() []proto.RDMonitor {
	monitorsFound = nil
	_, _, _ = pEnumDisplayMonitors.Call(0, 0, enumCallback, 0)
	out := monitorsFound
	monitorsFound = nil
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Primary != out[j].Primary {
			return out[i].Primary
		}
		return out[i].X < out[j].X || out[i].X == out[j].X && out[i].Y < out[j].Y
	})
	return out
}
