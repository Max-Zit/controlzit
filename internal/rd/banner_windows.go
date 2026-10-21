//go:build windows

package rd

import (
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The notice tells the person at the computer that a technician is
// connected. It is a small topmost bar at the top of the primary screen,
// excluded from the capture (Windows 10 2004+), so it does not cover what
// the technician sees.

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type msg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	_       uint32
}

type paintStruct struct {
	Hdc         uintptr
	Erase       int32
	Paint       rect
	Restore     int32
	IncUpdate   int32
	RGBReserved [32]byte
}

const (
	wmDestroy = 0x0002
	wmPaint   = 0x000F
	wmClose   = 0x0010

	wsPopup   = 0x80000000
	wsVisible = 0x10000000

	wsExTopmost    = 0x00000008
	wsExToolWindow = 0x00000080
	wsExLayered    = 0x00080000
	wsExNoActivate = 0x08000000

	lwaAlpha              = 0x2
	wdaExcludeFromCapture = 0x11

	dtCenter      = 0x01
	dtVCenter     = 0x04
	dtSingleLine  = 0x20
	dtEndEllipsis = 0x8000

	bannerW = 520
	bannerH = 34
)

// Banner shows the notice until Close.
type Banner struct {
	mu   sync.Mutex
	hwnd uintptr
	done chan struct{}
}

var (
	bannerText  []uint16
	bannerBrush uintptr
	bannerFont  uintptr
	wndProcOnce sync.Once
	wndProcPtr  uintptr
)

func bannerProc(hwnd uintptr, m uint32, wp, lp uintptr) uintptr {
	switch m {
	case wmPaint:
		var ps paintStruct
		hdc, _, _ := pBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps))) // #nosec G103 -- Win32 struct
		var rc rect
		_, _, _ = pGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))        // #nosec G103 -- Win32 struct
		_, _, _ = pFillRect.Call(hdc, uintptr(unsafe.Pointer(&rc)), bannerBrush) // #nosec G103 -- Win32 struct
		_, _, _ = pSetBkMode.Call(hdc, 1)                                        // TRANSPARENT
		_, _, _ = pSetTextColor.Call(hdc, 0x00FFFFFF)
		if bannerFont != 0 {
			_, _, _ = pSelectObject.Call(hdc, bannerFont)
		}
		_, _, _ = pDrawText.Call(hdc, uintptr(unsafe.Pointer(&bannerText[0])), uintptr(len(bannerText)-1), uintptr(unsafe.Pointer(&rc)), dtCenter|dtVCenter|dtSingleLine|dtEndEllipsis) // #nosec G103 -- Win32 buffers
		_, _, _ = pEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))                                                                                                                    // #nosec G103 -- Win32 struct
		return 0
	case wmClose:
		_, _, _ = pDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		_, _, _ = pPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProc.Call(hwnd, uintptr(m), wp, lp)
	return r
}

// ShowBanner displays text on the "Default" desktop of the session.
func ShowBanner(text string) *Banner {
	b := &Banner{done: make(chan struct{})}
	ready := make(chan struct{})
	go func() {
		defer close(b.done)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		name, _ := windows.UTF16PtrFromString("Default")
		if h, _, _ := pOpenDesktop.Call(uintptr(unsafe.Pointer(name)), 0, 0, desktopAllAccess); h != 0 { // #nosec G103 -- Win32 string
			_, _, _ = pSetThreadDesktop.Call(h)
		}
		wndProcOnce.Do(func() {
			wndProcPtr = syscall.NewCallback(bannerProc)
			bannerBrush, _, _ = pCreateSolidBrush.Call(0x00E5464F) // BGR of #4f46e5
			face, _ := windows.UTF16PtrFromString("Segoe UI")
			bannerFont, _, _ = pCreateFont.Call(^uintptr(17), 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(face))) // #nosec G103 -- height -18 px, semibold, ClearType
		})
		bannerText, _ = windows.UTF16FromString(text)
		cls, _ := windows.UTF16PtrFromString("ControlZitNotice")
		arrow, _, _ := pLoadCursor.Call(0, 32512)
		wc := wndClassEx{WndProc: wndProcPtr, ClassName: cls, Cursor: windows.Handle(arrow)}
		wc.Size = uint32(unsafe.Sizeof(wc))
		_, _, _ = pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))                                                                                         // #nosec G103 -- Win32 struct; fails harmlessly when already registered
		x := (metric(0) - bannerW) / 2                                                                                                                        // SM_CXSCREEN
		hwnd, _, _ := pCreateWindowEx.Call(wsExTopmost|wsExToolWindow|wsExLayered|wsExNoActivate, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(cls)), // #nosec G103 -- Win32 strings
			wsPopup|wsVisible, uintptr(x), 0, bannerW, bannerH, 0, 0, 0, 0)
		b.mu.Lock()
		b.hwnd = hwnd
		b.mu.Unlock()
		close(ready)
		if hwnd == 0 {
			return
		}
		_, _, _ = pSetLayeredAttrs.Call(hwnd, 0, 235, lwaAlpha)
		_, _, _ = pSetWindowDisplayAffin.Call(hwnd, wdaExcludeFromCapture)
		var m msg
		for {
			r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0) // #nosec G103 -- Win32 struct
			if r == 0 || int32(r) == -1 {
				return
			}
			_, _, _ = pTranslateMessage.Call(uintptr(unsafe.Pointer(&m))) // #nosec G103 -- Win32 struct
			_, _, _ = pDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))  // #nosec G103 -- Win32 struct
		}
	}()
	<-ready
	return b
}

// Close removes the notice.
func (b *Banner) Close() {
	b.mu.Lock()
	h := b.hwnd
	b.mu.Unlock()
	if h != 0 {
		_, _, _ = pPostMessage.Call(h, wmClose, 0, 0)
		<-b.done
	}
}
