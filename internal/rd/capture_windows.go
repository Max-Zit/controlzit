//go:build windows

package rd

import (
	"errors"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/max-zit/controlzit/internal/proto"
)

// Capturer grabs the whole virtual screen (all monitors) with GDI. It must
// be used from one locked OS thread, because it attaches that thread to
// the current input desktop (Default, or Winlogon for the sign-in screen
// and UAC prompts).
type Capturer struct {
	desk     uintptr
	deskName string
	screen   uintptr // screen DC
	mem      uintptr
	bmp      uintptr
	old      uintptr
	x, y     int
	w, h     int
	frame    Frame
	// Monitor is the display to capture (index into Monitors; -1 or out of
	// range: the whole virtual screen).
	Monitor  int
	monitors []proto.RDMonitor
	enumAt   time.Time
	vx, vy   int // virtual screen origin and size
	vw, vh   int
	// Desktop Duplication state (nil: GDI)
	dx    *dupl
	dxOff time.Time // GDI only until then (after a failure)
	dxErr error
	bits  uintptr // DIB section memory in DXGI mode
}

// Desktop is the name of the attached input desktop.
func (c *Capturer) Desktop() string { return c.deskName }

// Origin is the top-left of the virtual screen (negative with monitors
// left of or above the primary one).
func (c *Capturer) Origin() (int, int) { return c.x, c.y }

func deskName(h uintptr) string {
	var buf [256]uint16
	var n uint32
	r, _, _ := pGetUserObjectInfo.Call(h, uoiName, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2), uintptr(unsafe.Pointer(&n))) // #nosec G103 -- Win32 out-parameters
	if r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:])
}

// follow attaches the thread to the input desktop when it changed; it
// reports whether the desktop changed.
func (c *Capturer) follow() (bool, error) {
	h, _, err := pOpenInputDesktop.Call(0, 0, desktopAllAccess)
	if h == 0 {
		return false, errors.New("OpenInputDesktop: " + err.Error())
	}
	name := deskName(h)
	if name == c.deskName && c.desk != 0 {
		_, _, _ = pCloseDesktop.Call(h)
		return false, nil
	}
	c.release()
	if r, _, err := pSetThreadDesktop.Call(h); r == 0 {
		_, _, _ = pCloseDesktop.Call(h)
		return false, errors.New("SetThreadDesktop: " + err.Error())
	}
	if c.desk != 0 {
		_, _, _ = pCloseDesktop.Call(c.desk)
	}
	c.desk, c.deskName = h, name
	return true, nil
}

func (c *Capturer) release() {
	if c.mem != 0 {
		_, _, _ = pSelectObject.Call(c.mem, c.old)
		_, _, _ = pDeleteObject.Call(c.bmp)
		_, _, _ = pDeleteDC.Call(c.mem)
		c.mem, c.bmp = 0, 0
	}
	if c.screen != 0 {
		_, _, _ = pReleaseDC.Call(0, c.screen)
		c.screen = 0
	}
}

// Close releases the GDI objects and the desktop handle.
func (c *Capturer) Close() {
	c.closeDX()
	c.release()
	if c.desk != 0 {
		_, _, _ = pCloseDesktop.Call(c.desk)
		c.desk = 0
	}
}

// Capture returns the current screen (the frame buffer is reused) and
// whether the desktop or size changed since the last call.
func (c *Capturer) Capture() (*Frame, bool, error) {
	changed, err := c.follow()
	if err != nil {
		return nil, false, err
	}
	vx, vy, vw, vh := metric(smXVirtualScreen), metric(smYVirtualScreen), metric(smCXVirtualScreen), metric(smCYVirtualScreen)
	if vw <= 0 || vh <= 0 {
		return nil, false, errors.New("no screen")
	}
	if changed || vx != c.vx || vy != c.vy || vw != c.vw || vh != c.vh || time.Since(c.enumAt) > 2*time.Second {
		c.vx, c.vy, c.vw, c.vh = vx, vy, vw, vh
		c.enumAt = time.Now()
		if m := Monitors(); !sameMonitors(m, c.monitors) {
			c.monitors = m
			changed = true
		}
	}
	x, y, w, h := vx, vy, vw, vh
	if c.Monitor >= 0 && c.Monitor < len(c.monitors) {
		m := c.monitors[c.Monitor]
		x, y, w, h = m.X, m.Y, m.W, m.H
	}
	if UseDXGI && c.deskName == "Default" && time.Now().After(c.dxOff) && (c.Shown() >= 0 || len(c.monitors) == 1) {
		f, ch, err := c.captureDX(x, y, w, h, changed)
		if err == nil {
			return f, ch, nil
		}
		c.dxErr = err
		c.closeDX()
		c.dxOff = time.Now().Add(10 * time.Second)
		changed = true
	} else if c.dx != nil {
		c.closeDX()
		changed = true
	}
	if c.mem == 0 || w != c.w || h != c.h || x != c.x || y != c.y {
		c.release()
		changed = true
		c.x, c.y, c.w, c.h = x, y, w, h
		c.screen, _, _ = pGetDC.Call(0)
		if c.screen == 0 {
			return nil, false, errors.New("GetDC failed")
		}
		c.mem, _, _ = pCreateCompatibleDC.Call(c.screen)
		c.bmp, _, _ = pCreateCompatibleBitmap.Call(c.screen, uintptr(w), uintptr(h))
		if c.mem == 0 || c.bmp == 0 {
			c.release()
			return nil, false, errors.New("cannot create the capture bitmap")
		}
		c.old, _, _ = pSelectObject.Call(c.mem, c.bmp)
		c.frame = Frame{W: w, H: h, Pix: make([]byte, w*h*4)}
	}
	if r, _, err := pBitBlt.Call(c.mem, 0, 0, uintptr(w), uintptr(h), c.screen, uintptr(x), uintptr(y), c.rop()); r == 0 {
		// The desktop may have switched under us; reattach next time.
		c.release()
		c.deskName = ""
		return nil, false, errors.New("BitBlt: " + err.Error())
	}
	c.drawCursor()
	bi := bitmapInfoHeader{BitCount: 32, Planes: 1, Width: int32(w), Height: -int32(h)} // #nosec G115 -- screen size
	bi.Size = uint32(unsafe.Sizeof(bi))
	r, _, _ := pGetDIBits.Call(c.mem, c.bmp, 0, uintptr(h), uintptr(unsafe.Pointer(&c.frame.Pix[0])), uintptr(unsafe.Pointer(&bi)), 0) // #nosec G103 -- Win32 buffer
	if r == 0 {
		return nil, false, errors.New("GetDIBits failed")
	}
	return &c.frame, changed, nil
}

// drawCursor paints the mouse pointer into the captured bitmap.
func (c *Capturer) drawCursor() {
	ci := cursorInfo{}
	ci.Size = uint32(unsafe.Sizeof(ci))
	if r, _, _ := pGetCursorInfo.Call(uintptr(unsafe.Pointer(&ci))); r == 0 || ci.Flags&1 == 0 { // #nosec G103 -- Win32 struct
		return
	}
	var ii iconInfo
	hx, hy := int32(0), int32(0)
	if r, _, _ := pGetIconInfo.Call(uintptr(ci.Cursor), uintptr(unsafe.Pointer(&ii))); r != 0 { // #nosec G103 -- Win32 struct
		hx, hy = int32(ii.XHotspot), int32(ii.YHotspot) // #nosec G115 -- small hotspot offsets
		if ii.HbmMask != 0 {
			_, _, _ = pDeleteObject.Call(uintptr(ii.HbmMask))
		}
		if ii.HbmColor != 0 {
			_, _, _ = pDeleteObject.Call(uintptr(ii.HbmColor))
		}
	}
	px := int(ci.ScreenP.X-hx) - c.x
	py := int(ci.ScreenP.Y-hy) - c.y
	_, _, _ = pDrawIconEx.Call(c.mem, uintptr(px), uintptr(py), uintptr(ci.Cursor), 0, 0, 0, 0, diPNormal)
}

// NoCaptureBlt skips CAPTUREBLT (much faster BitBlt; with DWM composition
// layered windows are in the screen image anyway).
var NoCaptureBlt = true

func (c *Capturer) rop() uintptr {
	if NoCaptureBlt {
		return srcCopy
	}
	return srcCopy | captureBlt
}

// Monitors are the displays found at the last capture.
func (c *Capturer) Monitors() []proto.RDMonitor { return c.monitors }

// Shown is the index of the captured monitor (-1: all).
func (c *Capturer) Shown() int {
	if c.Monitor >= 0 && c.Monitor < len(c.monitors) {
		return c.Monitor
	}
	return -1
}

// ToVirtual turns a position in the captured image into one relative to
// the virtual screen, and returns the virtual screen size (for input).
func (c *Capturer) ToVirtual(x, y int) (int, int, int, int) {
	return x + c.x - c.vx, y + c.y - c.vy, c.vw, c.vh
}

func sameMonitors(a, b []proto.RDMonitor) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// UseDXGI captures with Desktop Duplication where it works.
var UseDXGI = true

// DXError is why Desktop Duplication was last given up (nil: never).
func (c *Capturer) DXError() error { return c.dxErr }

// UsingDXGI reports whether the last capture used Desktop Duplication.
func (c *Capturer) UsingDXGI() bool { return c.dx != nil && c.dx.have }

func (c *Capturer) closeDX() {
	if c.dx != nil {
		c.dx.close()
		c.dx = nil
		c.release()
		c.bits = 0
	}
}

// captureDX captures the display at x, y (w×h) with Desktop Duplication and
// draws the mouse pointer into a DIB section.
func (c *Capturer) captureDX(x, y, w, h int, changed bool) (*Frame, bool, error) {
	mon := proto.RDMonitor{X: x, Y: y, W: w, H: h}
	if c.dx == nil || c.dx.mon.X != x || c.dx.mon.Y != y || c.dx.mon.W != w || c.dx.mon.H != h {
		c.closeDX()
		c.release()
		d, err := newDupl(mon)
		if err != nil {
			return nil, false, err
		}
		c.dx = d
		changed = true
		c.screen, _, _ = pGetDC.Call(0)
		c.mem, _, _ = pCreateCompatibleDC.Call(c.screen)
		bi := bitmapInfoHeader{BitCount: 32, Planes: 1, Width: int32(w), Height: -int32(h)} // #nosec G115 -- screen size
		bi.Size = uint32(unsafe.Sizeof(bi))
		c.bmp, _, _ = pCreateDIBSection.Call(c.screen, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&c.bits)), 0, 0) // #nosec G103 -- Win32 out-parameter
		if c.mem == 0 || c.bmp == 0 || c.bits == 0 {
			return nil, false, errors.New("cannot create the DIB section")
		}
		c.old, _, _ = pSelectObject.Call(c.mem, c.bmp)
		c.x, c.y, c.w, c.h = x, y, w, h
		c.frame = Frame{W: w, H: h, Pix: make([]byte, w*h*4)}
	}
	if _, err := c.dx.next(0); err != nil {
		return nil, false, err
	}
	dib := unsafe.Slice((*byte)(ptrOf(c.bits)), w*h*4) // #nosec G103 -- DIB section of w×h pixels
	if c.dx.have {
		copy(dib, c.dx.clean)
	} else {
		// Some display drivers deliver the first image only after something
		// changes: until then GDI fills the same buffer.
		if r, _, err := pBitBlt.Call(c.mem, 0, 0, uintptr(w), uintptr(h), c.screen, uintptr(x), uintptr(y), c.rop()); r == 0 {
			return nil, false, errors.New("BitBlt: " + err.Error())
		}
	}
	c.drawCursor()
	_, _, _ = pGdiFlush.Call()
	copy(c.frame.Pix, dib)
	return &c.frame, changed, nil
}
