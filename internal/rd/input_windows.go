//go:build windows

package rd

import (
	"errors"
	"unicode/utf16"
	"unsafe"
)

// SendInput structures (64-bit layout).
type input struct {
	typ  uint32
	_    uint32
	data [32]byte
}

type mouseInput struct {
	dx, dy    int32
	mouseData uint32
	flags     uint32
	time      uint32
	_         uint32
	extra     uintptr
}

type keybdInput struct {
	vk, scan uint16
	flags    uint32
	time     uint32
	_        uint32
	extra    uintptr
}

const (
	inputMouse    = 0
	inputKeyboard = 1

	mouseMove      = 0x0001
	mouseLeftDown  = 0x0002
	mouseLeftUp    = 0x0004
	mouseRightDown = 0x0008
	mouseRightUp   = 0x0010
	mouseMidDown   = 0x0020
	mouseMidUp     = 0x0040
	mouseWheel     = 0x0800
	mouseVirtual   = 0x4000
	mouseAbsolute  = 0x8000

	keyExtended = 0x0001
	keyUp       = 0x0002
	keyUnicode  = 0x0004
	keyScancode = 0x0008
)

func send(in []input) error {
	if len(in) == 0 {
		return nil
	}
	r, _, err := pSendInput.Call(uintptr(len(in)), uintptr(unsafe.Pointer(&in[0])), unsafe.Sizeof(in[0])) // #nosec G103 -- Win32 array
	if int(r) != len(in) {
		return errors.New("SendInput: " + err.Error())
	}
	return nil
}

func mouse(m mouseInput) input {
	in := input{typ: inputMouse}
	*(*mouseInput)(unsafe.Pointer(&in.data[0])) = m // #nosec G103 -- union of the INPUT struct
	return in
}

func key(k keybdInput) input {
	in := input{typ: inputKeyboard}
	*(*keybdInput)(unsafe.Pointer(&in.data[0])) = k // #nosec G103 -- union of the INPUT struct
	return in
}

// Injector replays the technician's input on the input desktop; it must
// run on the thread of the Capturer (same desktop).
type Injector struct {
	buttons int
}

// Mouse moves to (x, y) in captured-frame pixels, applies button changes
// and the wheel; w, h is the size of the virtual screen.
func (j *Injector) Mouse(x, y, buttons, wheel, w, h int) error {
	if w < 2 || h < 2 {
		return nil
	}
	x, y = max(0, min(x, w-1)), max(0, min(y, h-1))
	// Absolute coordinates over the virtual desktop are 0..65535.
	m := mouseInput{dx: int32(x * 65535 / (w - 1)), dy: int32(y * 65535 / (h - 1)), flags: mouseMove | mouseAbsolute | mouseVirtual} // #nosec G115 -- 0..65535
	in := []input{mouse(m)}
	for _, b := range []struct{ bit, down, up uint32 }{{1, mouseLeftDown, mouseLeftUp}, {2, mouseRightDown, mouseRightUp}, {4, mouseMidDown, mouseMidUp}} {
		was, is := j.buttons&int(b.bit) != 0, buttons&int(b.bit) != 0
		switch {
		case is && !was:
			in = append(in, mouse(mouseInput{flags: b.down}))
		case was && !is:
			in = append(in, mouse(mouseInput{flags: b.up}))
		}
	}
	j.buttons = buttons
	if wheel != 0 {
		in = append(in, mouse(mouseInput{flags: mouseWheel, mouseData: uint32(int32(wheel))})) // #nosec G115 -- signed wheel delta as Windows expects it
	}
	return send(in)
}

// Key presses or releases a physical key.
func (j *Injector) Key(code string, down bool) error {
	sc, ext, ok := ScanCode(code)
	if !ok {
		return nil
	}
	f := uint32(keyScancode)
	if ext {
		f |= keyExtended
	}
	if !down {
		f |= keyUp
	}
	return send([]input{key(keybdInput{scan: sc, flags: f})})
}

// Type enters text as Unicode characters (paste from the technician).
func (j *Injector) Type(s string) error {
	var in []input
	for _, u := range utf16.Encode([]rune(s)) {
		if u == '\n' {
			u = '\r'
		}
		in = append(in, key(keybdInput{scan: u, flags: keyUnicode}), key(keybdInput{scan: u, flags: keyUnicode | keyUp}))
	}
	return send(in)
}

// ReleaseAll lets go of held mouse buttons (end of a session).
func (j *Injector) ReleaseAll() {
	var in []input
	for _, b := range []struct{ bit, up uint32 }{{1, mouseLeftUp}, {2, mouseRightUp}, {4, mouseMidUp}} {
		if j.buttons&int(b.bit) != 0 {
			in = append(in, mouse(mouseInput{flags: b.up}))
		}
	}
	j.buttons = 0
	_ = send(in)
}

// CtrlAltDel sends the secure attention sequence (needs SYSTEM).
func CtrlAltDel() error {
	if err := pSendSAS.Find(); err != nil {
		return err
	}
	_, _, _ = pSendSAS.Call(0)
	return nil
}
