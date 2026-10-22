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

// TestCaptureDXGI compares Desktop Duplication with GDI (desktop needed).
func TestCaptureDXGI(t *testing.T) {
	if os.Getenv("CZ_DESKTOP_TEST") == "" {
		t.Skip("set CZ_DESKTOP_TEST=1 on a machine with a desktop")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	setDPIAware()
	measure := func(dx bool) (time.Duration, *Capturer, *Frame) {
		UseDXGI = dx
		c := &Capturer{}
		f, _, err := c.Capture()
		if err != nil {
			t.Fatal(err)
		}
		const n = 30
		start := time.Now()
		for i := 0; i < n; i++ {
			if f, _, err = c.Capture(); err != nil {
				t.Fatal(err)
			}
		}
		return time.Since(start) / n, c, f
	}
	defer func() { UseDXGI = true }()
	gdi, cg, fg := measure(false)
	defer cg.Close()
	dx, cd, fd := measure(true)
	defer cd.Close()
	if !cd.UsingDXGI() {
		t.Skipf("Desktop Duplication not available here: %v (GDI %v)", cd.DXError(), gdi)
	}
	if fd.W != fg.W || fd.H != fg.H {
		t.Fatalf("sizes differ: DXGI %dx%d, GDI %dx%d", fd.W, fd.H, fg.W, fg.H)
	}
	// Both show the same desktop (allow small differences: clock, pointer).
	diff := 0
	for i := 0; i < len(fd.Pix); i += 4 * 101 {
		if fd.Pix[i] != fg.Pix[i] || fd.Pix[i+1] != fg.Pix[i+1] || fd.Pix[i+2] != fg.Pix[i+2] {
			diff++
		}
	}
	samples := len(fd.Pix) / (4 * 101)
	t.Logf("%dx%d: GDI %v, DXGI %v per frame; %d of %d samples differ", fd.W, fd.H, gdi, dx, diff, samples)
	if diff > samples/10 {
		t.Fatal("DXGI and GDI images differ too much")
	}
}
