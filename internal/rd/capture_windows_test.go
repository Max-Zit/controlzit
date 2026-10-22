//go:build windows

package rd

import (
	"os"
	"runtime"
	"testing"
)

// The capture needs an interactive desktop; CI services have none.
func TestCaptureScreen(t *testing.T) {
	if os.Getenv("CZ_DESKTOP_TEST") == "" {
		t.Skip("set CZ_DESKTOP_TEST=1 on a machine with a desktop")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	setDPIAware()
	var c Capturer
	defer c.Close()
	f, changed, err := c.Capture()
	if err != nil || !changed || f.W < 640 || f.H < 400 {
		t.Fatalf("capture: %v %v %+v", err, changed, f)
	}
	nonBlack := 0
	for i := 0; i < len(f.Pix); i += 4 * 97 {
		if f.Pix[i]|f.Pix[i+1]|f.Pix[i+2] != 0 {
			nonBlack++
		}
	}
	if nonBlack == 0 {
		t.Fatal("the captured screen is black")
	}
	e := &Encoder{Quality: 60}
	tiles, err := e.Encode(f)
	if err != nil || len(tiles) == 0 {
		t.Fatal(err)
	}
	t.Logf("%dx%d desktop %q, %d strips", f.W, f.H, c.Desktop(), len(tiles))
}

func TestBanner(t *testing.T) {
	if os.Getenv("CZ_DESKTOP_TEST") == "" {
		t.Skip("set CZ_DESKTOP_TEST=1 on a machine with a desktop")
	}
	b := ShowBanner("ControlZit test: a technician is connected")
	if b.hwnd == 0 {
		t.Fatal("no banner window")
	}
	b.Close()
}

func TestCaptureMonitor(t *testing.T) {
	if os.Getenv("CZ_DESKTOP_TEST") == "" {
		t.Skip("set CZ_DESKTOP_TEST=1 on a machine with a desktop")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	setDPIAware()
	var c Capturer
	defer c.Close()
	c.Monitor = -1
	all, _, err := c.Capture()
	if err != nil {
		t.Fatal(err)
	}
	aw, ah := all.W, all.H
	ms := c.Monitors()
	if len(ms) == 0 || !ms[0].Primary {
		t.Fatalf("monitors: %+v", ms)
	}
	c.Monitor = 0
	f, changed, err := c.Capture()
	if err != nil || (len(ms) > 1 && !changed) || f.W != ms[0].W || f.H != ms[0].H {
		t.Fatalf("primary: %v %v %dx%d, want %dx%d", err, changed, f.W, f.H, ms[0].W, ms[0].H)
	}
	// A click in the middle of the primary monitor maps into the virtual screen.
	vx, vy, vw, vh := c.ToVirtual(f.W/2, f.H/2)
	if vw != aw || vh != ah || vx < 0 || vy < 0 || vx >= vw || vy >= vh {
		t.Fatalf("ToVirtual: %d,%d in %dx%d", vx, vy, vw, vh)
	}
	t.Logf("%d monitors, all %dx%d, primary %dx%d", len(ms), aw, ah, f.W, f.H)
}
