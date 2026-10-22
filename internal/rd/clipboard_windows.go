//go:build windows

package rd

import (
	"context"
	"errors"
	"runtime"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/max-zit/controlzit/internal/proto"
)

// The clipboard belongs to the window station: the helper reads and writes
// it as text from a thread with its own message-only window (setting the
// clipboard needs an owner window, and other programs send that window
// messages, so the thread keeps pumping them).

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	pOpenClipboard              = user32.NewProc("OpenClipboard")
	pCloseClipboard             = user32.NewProc("CloseClipboard")
	pEmptyClipboard             = user32.NewProc("EmptyClipboard")
	pSetClipboardData           = user32.NewProc("SetClipboardData")
	pGetClipboardData           = user32.NewProc("GetClipboardData")
	pIsClipboardFormatAvailable = user32.NewProc("IsClipboardFormatAvailable")
	pGetClipboardSequenceNumber = user32.NewProc("GetClipboardSequenceNumber")
	pPeekMessage                = user32.NewProc("PeekMessageW")
	pTranslateMessageClip       = user32.NewProc("TranslateMessage")
	pDispatchMessageClip        = user32.NewProc("DispatchMessageW")
	pCreateWindowExClip         = user32.NewProc("CreateWindowExW")
	pDestroyWindowClip          = user32.NewProc("DestroyWindow")
	pGlobalAlloc                = kernel32.NewProc("GlobalAlloc")
	pGlobalLock                 = kernel32.NewProc("GlobalLock")
	pGlobalUnlock               = kernel32.NewProc("GlobalUnlock")
	pGlobalSize                 = kernel32.NewProc("GlobalSize")
	pGlobalFree                 = kernel32.NewProc("GlobalFree")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
	hwndMessage   = ^uintptr(2) // HWND_MESSAGE (-3)
	pmRemove      = 0x0001
)

// Clipboard exchanges text with the remote clipboard.
type Clipboard struct {
	req     chan func()
	hwnd    uintptr
	lastSeq uintptr
}

// StartClipboard runs the clipboard thread until ctx ends; onChange gets
// the text whenever another program copies text (not the text that was
// already there, nor the text set through Set).
func StartClipboard(ctx context.Context, onChange func(string)) (*Clipboard, error) {
	c := &Clipboard{req: make(chan func())}
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		cls, _ := windows.UTF16PtrFromString("STATIC")
		h, _, err := pCreateWindowExClip.Call(0, uintptr(unsafe.Pointer(cls)), 0, 0, 0, 0, 0, 0, hwndMessage, 0, 0, 0) // #nosec G103 -- Win32 string
		if h == 0 {
			ready <- errors.New("clipboard window: " + err.Error())
			return
		}
		c.hwnd = h
		defer func() { _, _, _ = pDestroyWindowClip.Call(h) }()
		c.lastSeq, _, _ = pGetClipboardSequenceNumber.Call()
		ready <- nil
		pump := time.NewTicker(50 * time.Millisecond)
		defer pump.Stop()
		poll := time.Now()
		var m msgClip
		for {
			select {
			case <-ctx.Done():
				return
			case f := <-c.req:
				f()
			case <-pump.C:
			}
			for {
				r, _, _ := pPeekMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0, pmRemove) // #nosec G103 -- Win32 struct
				if r == 0 {
					break
				}
				_, _, _ = pTranslateMessageClip.Call(uintptr(unsafe.Pointer(&m))) // #nosec G103 -- Win32 struct
				_, _, _ = pDispatchMessageClip.Call(uintptr(unsafe.Pointer(&m)))  // #nosec G103 -- Win32 struct
			}
			if time.Since(poll) >= 500*time.Millisecond {
				poll = time.Now()
				if seq, _, _ := pGetClipboardSequenceNumber.Call(); seq != c.lastSeq {
					c.lastSeq = seq
					if s, err := c.read(); err == nil && s != "" {
						onChange(s)
					}
				}
			}
		}
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return c, nil
}

type msgClip struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	X, Y    int32
	_       uint32
}

func (c *Clipboard) open() error {
	for i := 0; i < 20; i++ {
		if r, _, _ := pOpenClipboard.Call(c.hwnd); r != 0 {
			return nil
		}
		time.Sleep(25 * time.Millisecond) // another program has it open
	}
	return errors.New("the clipboard is in use")
}

// read returns the clipboard text (on the clipboard thread).
func (c *Clipboard) read() (string, error) {
	if r, _, _ := pIsClipboardFormatAvailable.Call(cfUnicodeText); r == 0 {
		return "", nil
	}
	if err := c.open(); err != nil {
		return "", err
	}
	defer func() { _, _, _ = pCloseClipboard.Call() }()
	h, _, _ := pGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return "", nil
	}
	p, _, _ := pGlobalLock.Call(h)
	if p == 0 {
		return "", nil
	}
	defer func() { _, _, _ = pGlobalUnlock.Call(h) }()
	size, _, _ := pGlobalSize.Call(h)
	n := int(size / 2)
	if n > proto.MaxClipboard { // UTF-16 units; trimmed again as UTF-8 below
		n = proto.MaxClipboard
	}
	u := unsafe.Slice((*uint16)(ptrOf(p)), n) // #nosec G103 -- locked global memory of n units
	for i, v := range u {
		if v == 0 {
			u = u[:i]
			break
		}
	}
	return clipText(string(utf16.Decode(u))), nil
}

// clipText trims text to MaxClipboard bytes on a character boundary.
func clipText(s string) string {
	if len(s) <= proto.MaxClipboard {
		return s
	}
	s = s[:proto.MaxClipboard]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// Set puts text on the remote clipboard.
func (c *Clipboard) Set(text string) error {
	text = clipText(text)
	done := make(chan error, 1)
	c.req <- func() { done <- c.set(text) }
	return <-done
}

func (c *Clipboard) set(text string) error {
	u := utf16.Encode([]rune(text))
	u = append(u, 0)
	h, _, _ := pGlobalAlloc.Call(gmemMoveable, uintptr(len(u)*2))
	if h == 0 {
		return errors.New("out of memory")
	}
	p, _, _ := pGlobalLock.Call(h)
	if p == 0 {
		_, _, _ = pGlobalFree.Call(h)
		return errors.New("GlobalLock failed")
	}
	copy(unsafe.Slice((*uint16)(ptrOf(p)), len(u)), u) // #nosec G103 -- allocated for len(u) units
	_, _, _ = pGlobalUnlock.Call(h)
	if err := c.open(); err != nil {
		_, _, _ = pGlobalFree.Call(h)
		return err
	}
	_, _, _ = pEmptyClipboard.Call()
	r, _, err := pSetClipboardData.Call(cfUnicodeText, h)
	_, _, _ = pCloseClipboard.Call()
	if r == 0 {
		_, _, _ = pGlobalFree.Call(h)
		return errors.New("SetClipboardData: " + err.Error())
	}
	// The system owns the memory now. Do not send this text back.
	c.lastSeq, _, _ = pGetClipboardSequenceNumber.Call()
	return nil
}

// ptrOf turns memory returned by GlobalLock into a pointer (the memory is
// not managed by Go, so the uintptr does not hide a Go pointer).
func ptrOf(p uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&p)) } // #nosec G103 -- Win32 global memory
