//go:build windows

package rd

import (
	"golang.org/x/sys/windows"
)

// Win32 functions that golang.org/x/sys/windows does not wrap.
var (
	user32 = windows.NewLazySystemDLL("user32.dll")
	gdi32  = windows.NewLazySystemDLL("gdi32.dll")

	pGetDC                  = user32.NewProc("GetDC")
	pReleaseDC              = user32.NewProc("ReleaseDC")
	pGetSystemMetrics       = user32.NewProc("GetSystemMetrics")
	pOpenInputDesktop       = user32.NewProc("OpenInputDesktop")
	pSetThreadDesktop       = user32.NewProc("SetThreadDesktop")
	pCloseDesktop           = user32.NewProc("CloseDesktop")
	pGetUserObjectInfo      = user32.NewProc("GetUserObjectInformationW")
	pOpenDesktop            = user32.NewProc("OpenDesktopW")
	pGetCursorInfo          = user32.NewProc("GetCursorInfo")
	pGetIconInfo            = user32.NewProc("GetIconInfo")
	pDrawIconEx             = user32.NewProc("DrawIconEx")
	pSendInput              = user32.NewProc("SendInput")
	pSetProcessDpiAwareCtx  = user32.NewProc("SetProcessDpiAwarenessContext")
	pSetProcessDPIAware     = user32.NewProc("SetProcessDPIAware")
	pRegisterClassEx        = user32.NewProc("RegisterClassExW")
	pCreateWindowEx         = user32.NewProc("CreateWindowExW")
	pDefWindowProc          = user32.NewProc("DefWindowProcW")
	pGetMessage             = user32.NewProc("GetMessageW")
	pDispatchMessage        = user32.NewProc("DispatchMessageW")
	pTranslateMessage       = user32.NewProc("TranslateMessage")
	pPostMessage            = user32.NewProc("PostMessageW")
	pPostQuitMessage        = user32.NewProc("PostQuitMessage")
	pDestroyWindow          = user32.NewProc("DestroyWindow")
	pBeginPaint             = user32.NewProc("BeginPaint")
	pEndPaint               = user32.NewProc("EndPaint")
	pFillRect               = user32.NewProc("FillRect")
	pDrawText               = user32.NewProc("DrawTextW")
	pSetLayeredAttrs        = user32.NewProc("SetLayeredWindowAttributes")
	pSetWindowDisplayAffin  = user32.NewProc("SetWindowDisplayAffinity")
	pGetClientRect          = user32.NewProc("GetClientRect")
	pLoadCursor             = user32.NewProc("LoadCursorW")
	pCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	pCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	pSelectObject           = gdi32.NewProc("SelectObject")
	pDeleteObject           = gdi32.NewProc("DeleteObject")
	pDeleteDC               = gdi32.NewProc("DeleteDC")
	pBitBlt                 = gdi32.NewProc("BitBlt")
	pGetDIBits              = gdi32.NewProc("GetDIBits")
	pCreateSolidBrush       = gdi32.NewProc("CreateSolidBrush")
	pSetTextColor           = gdi32.NewProc("SetTextColor")
	pSetBkMode              = gdi32.NewProc("SetBkMode")
	pCreateFont             = gdi32.NewProc("CreateFontW")

	sas      = windows.NewLazySystemDLL("sas.dll")
	pSendSAS = sas.NewProc("SendSAS")
)

const (
	smXVirtualScreen  = 76
	smYVirtualScreen  = 77
	smCXVirtualScreen = 78
	smCYVirtualScreen = 79

	srcCopy    = 0x00CC0020
	captureBlt = 0x40000000

	desktopAllAccess = 0x01FF
	uoiName          = 2

	diPNormal = 0x0003
)

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type point struct{ X, Y int32 }

type cursorInfo struct {
	Size    uint32
	Flags   uint32
	Cursor  windows.Handle
	ScreenP point
}

type iconInfo struct {
	FIcon    int32
	XHotspot uint32
	YHotspot uint32
	HbmMask  windows.Handle
	HbmColor windows.Handle
}

type rect struct{ Left, Top, Right, Bottom int32 }

func metric(i int) int {
	r, _, _ := pGetSystemMetrics.Call(uintptr(i))
	return int(int32(r)) // #nosec G115 -- system metrics are small signed values
}

// setDPIAware makes the process see real pixels on scaled displays.
func setDPIAware() {
	// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
	if pSetProcessDpiAwareCtx.Find() == nil {
		if r, _, _ := pSetProcessDpiAwareCtx.Call(^uintptr(3)); r != 0 {
			return
		}
	}
	_, _, _ = pSetProcessDPIAware.Call()
}

var pGetModuleHandle = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleHandleW")
