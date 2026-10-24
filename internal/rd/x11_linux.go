//go:build linux

package rd

import (
	"errors"
	"io"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/shm"
	"github.com/jezek/xgb/xfixes"
	"github.com/jezek/xgb/xproto"
	"github.com/jezek/xgb/xtest"
	"golang.org/x/sys/unix"
)

// X11 desktop: the helper connects to the X server named by DISPLAY (with
// the XAUTHORITY cookie the service found), reads the screen through
// MIT-SHM (or GetImage when shared memory cannot be used), draws the mouse
// pointer from XFixes into the frame and replays input through XTEST.

func init() { xgb.Logger = log.New(io.Discard, "", 0) }

type xDesktop struct {
	c      *xgb.Conn
	root   xproto.Window
	depth  byte
	w, h   int
	frame  Frame
	cursor bool // XFixes pointer image available

	// MIT-SHM
	shmOK  bool
	shmErr error // why shared memory is not used
	seg    shm.Seg
	shmID  int
	shmBuf []byte

	// keyboard
	minKey, maxKey xproto.Keycode
	perKey         int
	syms           map[xproto.Keysym]keyPos
	spare          xproto.Keycode
	buttons        int
}

type keyPos struct {
	code  xproto.Keycode
	shift bool
}

func openX() (*xDesktop, error) {
	c, err := xgb.NewConn()
	if err != nil {
		return nil, err
	}
	if err := xtest.Init(c); err != nil {
		c.Close()
		return nil, errors.New("the X server has no XTEST extension (needed for mouse and keyboard)")
	}
	setup := xproto.Setup(c)
	scr := setup.DefaultScreen(c)
	d := &xDesktop{c: c, root: scr.Root, depth: scr.RootDepth, minKey: setup.MinKeycode, maxKey: setup.MaxKeycode}
	if xfixes.Init(c) == nil {
		if _, err := xfixes.QueryVersion(c, 4, 0).Reply(); err == nil {
			d.cursor = true
		}
	}
	if err := shm.Init(c); err == nil {
		d.shmOK = true
	} else {
		d.shmErr = err
	}
	d.loadKeymap()
	return d, nil
}

func (d *xDesktop) Close() {
	d.dropShm()
	d.c.Close()
}

func (d *xDesktop) dropShm() {
	if d.shmBuf != nil {
		shm.Detach(d.c, d.seg)
		_ = unix.SysvShmDetach(d.shmBuf)
		d.shmBuf = nil
	}
}

// newShm makes a shared segment for a w×h screen. The X server attaches it
// with its own user (rootless Xorg runs as the signed-in user), so the
// segment belongs to that user (CZ_XSERVER_UID) and nobody else.
func (d *xDesktop) newShm(size int) error {
	d.dropShm()
	id, err := unix.SysvShmGet(unix.IPC_PRIVATE, size, unix.IPC_CREAT|0o600)
	if err != nil {
		return err
	}
	if uid, err := strconv.Atoi(os.Getenv("CZ_XSERVER_UID")); err == nil && uid != 0 {
		var desc unix.SysvShmDesc
		if _, err := unix.SysvShmCtl(id, unix.IPC_STAT, &desc); err == nil {
			desc.Perm.Uid = uint32(uid) // #nosec G115 -- a uid
			_, _ = unix.SysvShmCtl(id, unix.IPC_SET, &desc)
		}
	}
	buf, err := unix.SysvShmAttach(id, 0, 0)
	// Removed now: it goes away when both sides detach.
	_, _ = unix.SysvShmCtl(id, unix.IPC_RMID, nil)
	if err != nil {
		return err
	}
	seg, err := shm.NewSegId(d.c)
	if err != nil {
		_ = unix.SysvShmDetach(buf)
		return err
	}
	if err := shm.AttachChecked(d.c, seg, uint32(id), false).Check(); err != nil { // #nosec G115 -- a shm id
		_ = unix.SysvShmDetach(buf)
		return err
	}
	d.seg, d.shmID, d.shmBuf = seg, id, buf
	return nil
}

// Capture reads the whole screen into a BGRA frame.
func (d *xDesktop) Capture() (*Frame, error) {
	g, err := xproto.GetGeometry(d.c, xproto.Drawable(d.root)).Reply()
	if err != nil {
		return nil, err
	}
	w, h := int(g.Width), int(g.Height)
	if d.depth != 24 && d.depth != 32 {
		return nil, errors.New("only 24-bit X screens are supported (depth " + strconv.Itoa(int(d.depth)) + ")")
	}
	size := w * h * 4
	if w != d.w || h != d.h {
		d.w, d.h = w, h
		d.frame = Frame{W: w, H: h, Pix: make([]byte, size)}
		if d.shmOK {
			if err := d.newShm(size); err != nil {
				d.shmOK, d.shmErr = false, err
			}
		}
	}
	if d.shmOK && d.shmBuf != nil {
		_, err := shm.GetImage(d.c, xproto.Drawable(d.root), 0, 0, uint16(w), uint16(h), 0xffffffff, xproto.ImageFormatZPixmap, d.seg, 0).Reply() // #nosec G115 -- screen size
		if err == nil {
			copy(d.frame.Pix, d.shmBuf[:size])
		} else {
			d.shmOK, d.shmErr = false, err
			d.dropShm()
		}
	}
	if !d.shmOK {
		// Strips keep each reply small.
		for y := 0; y < h; y += 128 {
			sh := min(128, h-y)
			img, err := xproto.GetImage(d.c, xproto.ImageFormatZPixmap, xproto.Drawable(d.root), 0, int16(y), uint16(w), uint16(sh), 0xffffffff).Reply() // #nosec G115 -- screen size
			if err != nil {
				return nil, err
			}
			copy(d.frame.Pix[y*w*4:], img.Data)
		}
	}
	for i := 3; i < size; i += 4 {
		d.frame.Pix[i] = 0xff
	}
	if d.cursor {
		d.drawCursor()
	}
	return &d.frame, nil
}

// drawCursor blends the pointer image (premultiplied ARGB) into the frame.
func (d *xDesktop) drawCursor() {
	cur, err := xfixes.GetCursorImage(d.c).Reply()
	if err != nil {
		return
	}
	cw, ch := int(cur.Width), int(cur.Height)
	x0, y0 := int(cur.X)-int(cur.Xhot), int(cur.Y)-int(cur.Yhot)
	f := &d.frame
	for cy := 0; cy < ch; cy++ {
		y := y0 + cy
		if y < 0 || y >= f.H {
			continue
		}
		for cx := 0; cx < cw; cx++ {
			x := x0 + cx
			if x < 0 || x >= f.W || cy*cw+cx >= len(cur.CursorImage) {
				continue
			}
			p := cur.CursorImage[cy*cw+cx]
			a := p >> 24
			if a == 0 {
				continue
			}
			o := (y*f.W + x) * 4
			inv := 255 - a
			for k := 0; k < 3; k++ {
				v := (p>>(8*k))&0xff + uint32(f.Pix[o+k])*inv/255
				f.Pix[o+k] = byte(min(v, 255)) // #nosec G115 -- clamped
			}
		}
	}
}

// ---- input

// evdevCodes are the Linux input codes of the extended keys; the other
// keys have the same number as their set-1 scan code. X keycodes are the
// evdev codes plus 8.
var evdevCodes = map[string]int{
	"NumpadEnter": 96, "ControlRight": 97, "NumpadDivide": 98, "PrintScreen": 99, "AltRight": 100,
	"Home": 102, "ArrowUp": 103, "PageUp": 104, "ArrowLeft": 105, "ArrowRight": 106, "End": 107,
	"ArrowDown": 108, "PageDown": 109, "Insert": 110, "Delete": 111, "MetaLeft": 125, "MetaRight": 126,
	"ContextMenu": 127,
}

func xKeycode(code string) (xproto.Keycode, bool) {
	if v, ok := evdevCodes[code]; ok {
		return xproto.Keycode(v + 8), true // #nosec G115 -- the table holds codes below 128
	}
	sc, ext, ok := ScanCode(code)
	if !ok || ext {
		return 0, false
	}
	return xproto.Keycode(sc + 8), true // #nosec G115 -- scan codes are below 0x60
}

func (d *xDesktop) fake(typ byte, detail byte, x, y int16) {
	xtest.FakeInput(d.c, typ, detail, 0, d.root, x, y, 0)
}

// Mouse moves the pointer and sets the buttons (1 left, 2 right, 4
// middle); a positive wheel scrolls up.
func (d *xDesktop) Mouse(x, y, buttons, wheel int) {
	d.fake(xproto.MotionNotify, 0, int16(x), int16(y)) // #nosec G115 -- screen coordinates
	for bit, b := range map[int]byte{1: 1, 2: 3, 4: 2} {
		was, is := d.buttons&bit != 0, buttons&bit != 0
		if is && !was {
			d.fake(xproto.ButtonPress, b, 0, 0)
		} else if was && !is {
			d.fake(xproto.ButtonRelease, b, 0, 0)
		}
	}
	d.buttons = buttons
	for n := wheel; n != 0; {
		b := byte(4)
		if n < 0 {
			b = 5
			n = min(0, n+120)
		} else {
			n = max(0, n-120)
		}
		d.fake(xproto.ButtonPress, b, 0, 0)
		d.fake(xproto.ButtonRelease, b, 0, 0)
	}
	d.c.Sync()
}

// Key presses or releases a physical key; the remote layout applies.
func (d *xDesktop) Key(code string, down bool) {
	k, ok := xKeycode(code)
	if !ok {
		return
	}
	t := byte(xproto.KeyRelease)
	if down {
		t = xproto.KeyPress
	}
	d.fake(t, byte(k), 0, 0)
	d.c.Sync()
}

// ReleaseAll lets go of the buttons (keys are released by the browser).
func (d *xDesktop) ReleaseAll() { d.Mouse(0, 0, 0, 0) }

func (d *xDesktop) loadKeymap() {
	d.syms = map[xproto.Keysym]keyPos{}
	n := int(d.maxKey) - int(d.minKey) + 1
	m, err := xproto.GetKeyboardMapping(d.c, d.minKey, byte(n)).Reply() // #nosec G115 -- at most 255 keycodes
	if err != nil || m.KeysymsPerKeycode == 0 {
		return
	}
	d.perKey = int(m.KeysymsPerKeycode)
	for i := 0; i < n; i++ {
		row := m.Keysyms[i*d.perKey : (i+1)*d.perKey]
		code := xproto.Keycode(int(d.minKey) + i) // #nosec G115 -- a keycode
		empty := true
		for lvl, s := range row {
			if s != 0 {
				empty = false
			}
			if lvl < 2 && s != 0 {
				if _, ok := d.syms[s]; !ok {
					d.syms[s] = keyPos{code, lvl == 1}
				}
			}
		}
		if empty {
			d.spare = code // the highest free keycode
		}
	}
}

func keysymOf(r rune) xproto.Keysym {
	switch {
	case r == '\n' || r == '\r':
		return 0xff0d
	case r == '\t':
		return 0xff09
	case r >= 0x20 && r <= 0x7e, r >= 0xa0 && r <= 0xff:
		return xproto.Keysym(r) // #nosec G115 -- Latin-1
	}
	return xproto.Keysym(0x01000000 | r) // #nosec G115 -- Unicode keysym
}

// Type types text with whatever keys produce it; a character the layout
// lacks goes through a free keycode mapped to it for the moment.
func (d *xDesktop) Type(text string) {
	const shiftL = 50
	for _, r := range text {
		ks := keysymOf(r)
		pos, ok := d.syms[ks]
		temp := false
		if !ok {
			if d.spare == 0 || d.perKey == 0 {
				continue
			}
			syms := make([]xproto.Keysym, d.perKey)
			for i := range syms {
				syms[i] = ks
			}
			xproto.ChangeKeyboardMapping(d.c, 1, d.spare, byte(d.perKey), syms) // #nosec G115 -- small
			d.c.Sync()
			time.Sleep(30 * time.Millisecond)
			pos, temp = keyPos{d.spare, false}, true
		}
		if pos.shift {
			d.fake(xproto.KeyPress, shiftL, 0, 0)
		}
		d.fake(xproto.KeyPress, byte(pos.code), 0, 0)
		d.fake(xproto.KeyRelease, byte(pos.code), 0, 0)
		if pos.shift {
			d.fake(xproto.KeyRelease, shiftL, 0, 0)
		}
		d.c.Sync()
		if temp {
			time.Sleep(30 * time.Millisecond)
			xproto.ChangeKeyboardMapping(d.c, 1, d.spare, byte(d.perKey), make([]xproto.Keysym, d.perKey)) // #nosec G115 -- small
			d.c.Sync()
		}
	}
}

// ---- notice

// xBanner is a small always-on-top bar at the top of the screen.
type xBanner struct {
	c   *xgb.Conn
	win xproto.Window
	gc  xproto.Gcontext
	txt string
	w   int
}

func showXBanner(text string) (*xBanner, error) {
	c, err := xgb.NewConn()
	if err != nil {
		return nil, err
	}
	scr := xproto.Setup(c).DefaultScreen(c)
	ascii := make([]byte, 0, len(text))
	for _, r := range text {
		if r >= 0x20 && r < 0x7f {
			ascii = append(ascii, byte(r))
		} else {
			ascii = append(ascii, '?')
		}
	}
	if len(ascii) > 200 {
		ascii = ascii[:200]
	}
	b := &xBanner{c: c, txt: string(ascii)}
	font, _ := xproto.NewFontId(c)
	fontOK := xproto.OpenFontChecked(c, font, uint16(len("-misc-fixed-bold-r-normal--18-*-*-*-*-*-iso8859-1")), "-misc-fixed-bold-r-normal--18-*-*-*-*-*-iso8859-1").Check() == nil
	if !fontOK {
		fontOK = xproto.OpenFontChecked(c, font, 5, "fixed").Check() == nil
	}
	charW := 9
	b.w = min(int(scr.WidthInPixels), len(ascii)*charW+32)
	x := (int(scr.WidthInPixels) - b.w) / 2
	b.win, _ = xproto.NewWindowId(c)
	const bg, fg = 0x2563eb, 0xffffff
	xproto.CreateWindow(c, scr.RootDepth, b.win, scr.Root, int16(x), 0, uint16(b.w), 28, 0, // #nosec G115 -- screen size
		xproto.WindowClassInputOutput, scr.RootVisual,
		xproto.CwBackPixel|xproto.CwOverrideRedirect|xproto.CwEventMask,
		[]uint32{bg, 1, xproto.EventMaskExposure})
	b.gc, _ = xproto.NewGcontextId(c)
	mask, vals := uint32(xproto.GcForeground|xproto.GcBackground), []uint32{fg, bg}
	if fontOK {
		mask |= xproto.GcFont
		vals = append(vals, uint32(font))
	}
	xproto.CreateGC(c, b.gc, xproto.Drawable(b.win), mask, vals)
	xproto.MapWindow(c, b.win)
	b.draw()
	go b.loop()
	return b, nil
}

func (b *xBanner) draw() {
	xproto.ImageText8(b.c, byte(len(b.txt)), xproto.Drawable(b.win), b.gc, 16, 20, b.txt) // #nosec G115 -- at most 200
	b.c.Sync()
}

// loop redraws after an expose and keeps the bar above other windows.
func (b *xBanner) loop() {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	evs := make(chan struct{}, 1)
	go func() {
		for {
			ev, err := b.c.WaitForEvent()
			if ev == nil && err == nil {
				close(evs)
				return
			}
			if _, ok := ev.(xproto.ExposeEvent); ok {
				select {
				case evs <- struct{}{}:
				default:
				}
			}
		}
	}()
	for {
		select {
		case _, ok := <-evs:
			if !ok {
				return
			}
			b.draw()
		case <-tick.C:
			xproto.ConfigureWindow(b.c, b.win, xproto.ConfigWindowStackMode, []uint32{xproto.StackModeAbove})
			b.draw()
		}
	}
}

func (b *xBanner) Close() {
	if b != nil {
		b.c.Close()
	}
}
