//go:build windows

package rd

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
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
	x, y, w, h := metric(smXVirtualScreen), metric(smYVirtualScreen), metric(smCXVirtualScreen), metric(smCYVirtualScreen)
	if w <= 0 || h <= 0 {
		return nil, false, errors.New("no screen")
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
