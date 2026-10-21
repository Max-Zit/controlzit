//go:build windows

package rd

import (
	"os"
	"runtime"
	"testing"
	"time"
)

// TestCaptureSpeed reports how long capture and encoding take (desktop needed).
func TestCaptureSpeed(t *testing.T) {
	if os.Getenv("CZ_DESKTOP_TEST") == "" {
		t.Skip("set CZ_DESKTOP_TEST=1 on a machine with a desktop")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	setDPIAware()
	var c Capturer
	defer c.Close()
	c.Capture()
	const n = 20
	NoCaptureBlt = false
	start0 := time.Now()
	for i := 0; i < n; i++ {
		c.Capture()
	}
	t.Logf("with CAPTUREBLT: %v", time.Since(start0)/n)
	NoCaptureBlt = true
	start := time.Now()
	var f *Frame
	for i := 0; i < n; i++ {
		f, _, _ = c.Capture()
	}
	capt := time.Since(start) / n
	e := &Encoder{Quality: 65}
	start = time.Now()
	tiles, _ := e.Encode(f)
	full := time.Since(start)
	size := 0
	for _, x := range tiles {
		size += len(x.Data)
	}
	start = time.Now()
	for i := 0; i < n; i++ {
		e.Encode(f)
	}
	same := time.Since(start) / n
	t.Logf("%dx%d: capture %v, full encode %v (%d KB), unchanged frame %v", f.W, f.H, capt, full, size>>10, same)
}
