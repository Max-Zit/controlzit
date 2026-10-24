//go:build windows

// Package tray is the ControlZit icon in the notification area: it shows
// that the computer is managed and whether the agent is connected.
package tray

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/max-zit/controlzit/internal/agent"
)

var (
	user32  = windows.NewLazySystemDLL("user32.dll")
	shell32 = windows.NewLazySystemDLL("shell32.dll")
	kernel  = windows.NewLazySystemDLL("kernel32.dll")

	pRegisterClassEx   = user32.NewProc("RegisterClassExW")
	pCreateWindowEx    = user32.NewProc("CreateWindowExW")
	pDefWindowProc     = user32.NewProc("DefWindowProcW")
	pGetMessage        = user32.NewProc("GetMessageW")
	pTranslateMessage  = user32.NewProc("TranslateMessage")
	pDispatchMessage   = user32.NewProc("DispatchMessageW")
	pPostQuitMessage   = user32.NewProc("PostQuitMessage")
	pSetTimer          = user32.NewProc("SetTimer")
	pCreatePopupMenu   = user32.NewProc("CreatePopupMenu")
	pAppendMenu        = user32.NewProc("AppendMenuW")
	pTrackPopupMenu    = user32.NewProc("TrackPopupMenu")
	pDestroyMenu       = user32.NewProc("DestroyMenu")
	pGetCursorPos      = user32.NewProc("GetCursorPos")
	pSetForeground     = user32.NewProc("SetForegroundWindow")
	pRegisterWindowMsg = user32.NewProc("RegisterWindowMessageW")
	pLoadIcon          = user32.NewProc("LoadIconW")
	pSetMenuDefault    = user32.NewProc("SetMenuDefaultItem")
	pFindWindow        = user32.NewProc("FindWindowW")
	pPostMessage       = user32.NewProc("PostMessageW")
	pShellNotifyIcon   = shell32.NewProc("Shell_NotifyIconW")
	pExtractIconEx     = shell32.NewProc("ExtractIconExW")
	pGetModuleHandle   = kernel.NewProc("GetModuleHandleW")
)

const (
	wmTimer    = 0x0113
	wmCommand  = 0x0111
	wmDestroy  = 0x0002
	wmApp      = 0x8000
	wmRButtonU = 0x0205
	wmLButtonU = 0x0202
	wmLButtonD = 0x0203 // double click

	nimAdd    = 0
	nimModify = 1
	nimDelete = 2
	nifMsg    = 0x1
	nifIcon   = 0x2
	nifTip    = 0x4

	mfString    = 0x0
	mfGrayed    = 0x1
	mfSeparator = 0x800
	tpmReturn   = 0x0100
	tpmRight    = 0x0008

	cmdHide = 100
	cmdOpen = 101
)

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

type notifyIconData struct {
	Size            uint32
	Wnd             uintptr
	ID              uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            uintptr
	Tip             [128]uint16
	State           uint32
	StateMask       uint32
	Info            [256]uint16
	Version         uint32
	InfoTitle       [64]uint16
	InfoFlags       uint32
	GUID            windows.GUID
	BalloonIcon     uintptr
}

type point struct{ X, Y int32 }

type msg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	_       uint32
}

const callbackMsg = wmApp + 1

// openMsg asks a running tray to open its window (controlzit-tray --open).
const openMsg = wmApp + 2

type trayState struct {
	statusPath     string
	hwnd           uintptr
	icon           uintptr
	taskbarCreated uint32
	iconOn         uintptr
	iconOff        uintptr
	shownOn        bool
}

var st trayState

func utf16(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

// statusLines describes the agent for the menu and the tooltip.
func statusLines() (title, state, place string) {
	s, err := agent.ReadStatus(st.statusPath)
	title = "ControlZit Agent"
	if err != nil {
		return title, "Agent status unknown (is the service running?)", ""
	}
	if s.Version != "" {
		title += " " + s.Version
	}
	stale := time.Since(s.Updated) > 3*time.Minute
	switch {
	case s.Connected && !stale:
		state = "Connected to " + s.Server
	case stale:
		state = "Agent not running"
	default:
		state = "Not connected to " + s.Server
	}
	if s.Customer != "" {
		place = "Managed by " + s.Customer
		if s.Site != "" {
			place += " / " + s.Site
		}
	}
	return title, state, place
}

// connectedNow reports whether the agent is connected (fresh status).
func connectedNow() bool {
	s, err := agent.ReadStatus(st.statusPath)
	return err == nil && s.Connected && time.Since(s.Updated) <= 3*time.Minute
}

// stateIcon is the icon for the current state (green dot: connected).
func stateIcon() uintptr {
	st.shownOn = connectedNow()
	if st.shownOn && st.iconOn != 0 {
		return st.iconOn
	}
	if !st.shownOn && st.iconOff != 0 {
		return st.iconOff
	}
	return st.icon
}

func setTip() {
	title, state, _ := statusLines()
	nid := notifyIconData{Wnd: st.hwnd, ID: 1, Flags: nifTip | nifIcon, Icon: stateIcon()}
	nid.Size = uint32(unsafe.Sizeof(nid))
	copy(nid.Tip[:127], windows.StringToUTF16(title+"\n"+state))
	_, _, _ = pShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&nid))) // #nosec G103 -- Win32 struct
}

func addIcon() error {
	title, state, _ := statusLines()
	nid := notifyIconData{Wnd: st.hwnd, ID: 1, Flags: nifMsg | nifIcon | nifTip, CallbackMessage: callbackMsg, Icon: stateIcon()}

	nid.Size = uint32(unsafe.Sizeof(nid))
	copy(nid.Tip[:127], windows.StringToUTF16(title+"\n"+state))
	if r, _, err := pShellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(&nid))); r == 0 { // #nosec G103 -- Win32 struct
		return fmt.Errorf("Shell_NotifyIcon: %w", err)
	}
	return nil
}

func removeIcon() {
	nid := notifyIconData{Wnd: st.hwnd, ID: 1}
	nid.Size = uint32(unsafe.Sizeof(nid))
	_, _, _ = pShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&nid))) // #nosec G103 -- Win32 struct
}

func showMenu() {
	title, state, place := statusLines()
	m, _, _ := pCreatePopupMenu.Call()
	if m == 0 {
		return
	}
	defer func() { _, _, _ = pDestroyMenu.Call(m) }()
	add := func(flags uintptr, id uintptr, text string) {
		_, _, _ = pAppendMenu.Call(m, flags, id, uintptr(unsafe.Pointer(utf16(text)))) // #nosec G103 -- Win32 string
	}
	add(mfString, cmdOpen, "Open ControlZit Agent")
	_, _, _ = pSetMenuDefault.Call(m, cmdOpen, 0)
	_, _, _ = pAppendMenu.Call(m, mfSeparator, 0, 0)
	add(mfString|mfGrayed, 1, title)
	add(mfString|mfGrayed, 2, state)
	if place != "" {
		add(mfString|mfGrayed, 3, place)
	}
	_, _, _ = pAppendMenu.Call(m, mfSeparator, 0, 0)
	add(mfString, cmdHide, "Hide this icon until the next sign-in")
	var p point
	_, _, _ = pGetCursorPos.Call(uintptr(unsafe.Pointer(&p))) // #nosec G103 -- Win32 out-parameter
	_, _, _ = pSetForeground.Call(st.hwnd)
	cmd, _, _ := pTrackPopupMenu.Call(m, tpmReturn|tpmRight, uintptr(p.X), uintptr(p.Y), 0, st.hwnd, 0) // #nosec G115 -- screen coordinates as Win32 arguments
	if cmd == cmdOpen {
		win.open()
	}
	if cmd == cmdHide {
		removeIcon()
		_, _, _ = pPostQuitMessage.Call(0)
	}
}

func wndProc(hwnd uintptr, m uint32, wp, lp uintptr) uintptr {
	switch {
	case m == callbackMsg:
		switch lp {
		case wmLButtonU, wmLButtonD:
			win.open()
		case wmRButtonU:
			showMenu()
		}
		return 0
	case m == openMsg:
		win.open()
		return 0
	case m == wmTimer:
		setTip()
		return 0
	case st.taskbarCreated != 0 && m == st.taskbarCreated:
		_ = addIcon() // Explorer restarted
		return 0
	case m == wmDestroy:
		_, _, _ = pPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProc.Call(hwnd, uintptr(m), wp, lp)
	return r
}

// Run shows the icon until the user hides it or the session ends. Only one
// icon runs per session.
func Run(statusPath string, open bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	mu, err := windows.CreateMutex(nil, false, utf16(`Local\ControlZitTray`))
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		// Already running in this session: ask it to open the window.
		if open {
			if h, _, _ := pFindWindow.Call(uintptr(unsafe.Pointer(utf16("ControlZitTray"))), 0); h != 0 { // #nosec G103 -- Win32 string
				_, _, _ = pPostMessage.Call(h, openMsg, 0, 0)
			}
		}
		return nil
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(mu)
	st.statusPath = statusPath
	inst, _, _ := pGetModuleHandle.Call(0)
	exe, _ := os.Executable()
	var small uintptr
	_, _, _ = pExtractIconEx.Call(uintptr(unsafe.Pointer(utf16(exe))), 0, 0, uintptr(unsafe.Pointer(&small)), 1) // #nosec G103 -- Win32 out-parameter
	if small == 0 {
		small, _, _ = pLoadIcon.Call(0, 32512) // IDI_APPLICATION
	}
	st.icon = small
	st.iconOn = loadIcon("connected.ico", icoConnected, smallIconSize())
	st.iconOff = loadIcon("offline.ico", icoOffline, smallIconSize())
	cls := utf16("ControlZitTray")
	wc := wndClassEx{WndProc: syscall.NewCallback(wndProc), Instance: windows.Handle(inst), ClassName: cls}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if r, _, err := pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r == 0 { // #nosec G103 -- Win32 struct
		return fmt.Errorf("RegisterClassEx: %w", err)
	}
	st.hwnd, _, err = pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(cls)), 0, 0, 0, 0, 0, 0, 0, inst, 0) // #nosec G103 -- Win32 strings
	if st.hwnd == 0 {
		return fmt.Errorf("CreateWindowEx: %w", err)
	}
	tc, _, _ := pRegisterWindowMsg.Call(uintptr(unsafe.Pointer(utf16("TaskbarCreated")))) // #nosec G103 -- Win32 string
	st.taskbarCreated = uint32(tc)                                                        // #nosec G115 -- message IDs are 16-bit
	// At sign-in the taskbar may not exist yet: retry for a minute.
	for i := 0; ; i++ {
		if err = addIcon(); err == nil {
			break
		}
		if i == 30 {
			return err
		}
		time.Sleep(2 * time.Second)
	}
	defer removeIcon()
	_, _, _ = pSetTimer.Call(st.hwnd, 1, 10000, 0)
	if open {
		win.open()
	}
	var m msg
	for {
		r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0) // #nosec G103 -- Win32 struct
		if r == 0 || int32(r) == -1 {                                     // #nosec G115 -- GetMessage returns -1 on error
			return nil
		}
		_, _, _ = pTranslateMessage.Call(uintptr(unsafe.Pointer(&m))) // #nosec G103 -- Win32 struct
		_, _, _ = pDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))  // #nosec G103 -- Win32 struct
	}
}
