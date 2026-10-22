//go:build windows

package rd

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/max-zit/controlzit/internal/proto"
)

// Desktop Duplication (DXGI): the graphics driver hands over the finished
// desktop image of one display, much faster than GDI. It works on the
// user's desktop only; the sign-in and UAC screens, rotated displays and
// "all monitors" use GDI.

var (
	d3d11              = windows.NewLazySystemDLL("d3d11.dll")
	pD3D11CreateDevice = d3d11.NewProc("D3D11CreateDevice")
	pGdiFlush          = gdi32.NewProc("GdiFlush")
	pCreateDIBSection  = gdi32.NewProc("CreateDIBSection")
)

var (
	iidIDXGIDevice     = windows.GUID{Data1: 0x54ec77fa, Data2: 0x1377, Data3: 0x44e6, Data4: [8]byte{0x8c, 0x32, 0x88, 0xfd, 0x5f, 0x44, 0xc8, 0x4c}}
	iidIDXGIOutput1    = windows.GUID{Data1: 0x00cddea8, Data2: 0x939b, Data3: 0x4b83, Data4: [8]byte{0xa3, 0x40, 0xa6, 0x85, 0x22, 0x66, 0x66, 0xcc}}
	iidID3D11Texture2D = windows.GUID{Data1: 0x6f15aaf2, Data2: 0xd208, Data3: 0x4e89, Data4: [8]byte{0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c}}
)

// vtable slots
const (
	vtQueryInterface      = 0
	vtRelease             = 2
	vtDevCreateTexture2D  = 5
	vtDXGIDevGetAdapter   = 7
	vtAdapterEnumOutputs  = 7
	vtOutputGetDesc       = 7
	vtOutput1DuplicateOut = 22
	vtDupAcquireNextFrame = 8
	vtDupReleaseFrame     = 14
	vtCtxMap              = 14
	vtCtxUnmap            = 15
	vtCtxCopyResource     = 47
)

const (
	dxgiErrWaitTimeout = 0x887A0027
	dxgiErrNotFound    = 0x887A0002
	d3dDriverHardware  = 1
	d3d11SDKVersion    = 7
	formatBGRA         = 87 // DXGI_FORMAT_B8G8R8A8_UNORM
	usageStaging       = 3
	cpuAccessRead      = 0x20000
	mapRead            = 1
)

// comCall calls method idx of a COM object.
func comCall(obj uintptr, idx int, args ...uintptr) uintptr {
	vtbl := *(*uintptr)(ptrOf(obj))
	fn := *(*uintptr)(ptrOf(vtbl + uintptr(idx)*unsafe.Sizeof(uintptr(0))))
	r, _, _ := syscall.SyscallN(fn, append([]uintptr{obj}, args...)...)
	return r
}

func comRelease(obj *uintptr) {
	if *obj != 0 {
		comCall(*obj, vtRelease)
		*obj = 0
	}
}

func failed(hr uintptr) bool { return int32(hr) < 0 } // #nosec G115 -- HRESULT is a signed 32-bit value

type outputDesc struct {
	DeviceName [32]uint16
	Coords     rect
	Attached   int32
	Rotation   uint32
	Monitor    uintptr
}

type texture2DDesc struct {
	Width, Height, MipLevels, ArraySize, Format uint32
	SampleCount, SampleQuality                  uint32
	Usage, BindFlags, CPUAccessFlags, MiscFlags uint32
}

type mappedSubresource struct {
	Data       uintptr
	RowPitch   uint32
	DepthPitch uint32
}

type duplFrameInfo struct {
	LastPresentTime     int64
	LastMouseUpdateTime int64
	AccumulatedFrames   uint32
	_                   [64]byte // rest of DXGI_OUTDUPL_FRAME_INFO (not used)
}

// dupl duplicates one display.
type dupl struct {
	mon     proto.RDMonitor
	dev     uintptr
	ctx     uintptr
	dup     uintptr
	staging uintptr
	w, h    int
	clean   []byte // the last image, without the mouse pointer
	have    bool
}

func newDupl(mon proto.RDMonitor) (*dupl, error) {
	d := &dupl{mon: mon, w: mon.W, h: mon.H}
	var level uint32
	if hr, _, _ := pD3D11CreateDevice.Call(0, d3dDriverHardware, 0, 0, 0, 0, d3d11SDKVersion,
		uintptr(unsafe.Pointer(&d.dev)), uintptr(unsafe.Pointer(&level)), uintptr(unsafe.Pointer(&d.ctx))); failed(hr) { // #nosec G103 -- COM out-parameters
		return nil, fmt.Errorf("D3D11CreateDevice: 0x%x", hr)
	}
	ok := false
	defer func() {
		if !ok {
			d.close()
		}
	}()
	var dxdev, adapter uintptr
	defer comRelease(&dxdev)
	defer comRelease(&adapter)
	if hr := comCall(d.dev, vtQueryInterface, uintptr(unsafe.Pointer(&iidIDXGIDevice)), uintptr(unsafe.Pointer(&dxdev))); failed(hr) { // #nosec G103 -- COM
		return nil, fmt.Errorf("IDXGIDevice: 0x%x", hr)
	}
	if hr := comCall(dxdev, vtDXGIDevGetAdapter, uintptr(unsafe.Pointer(&adapter))); failed(hr) { // #nosec G103 -- COM
		return nil, fmt.Errorf("GetAdapter: 0x%x", hr)
	}
	for i := uintptr(0); ; i++ {
		var out uintptr
		hr := comCall(adapter, vtAdapterEnumOutputs, i, uintptr(unsafe.Pointer(&out))) // #nosec G103 -- COM
		if hr == dxgiErrNotFound || failed(hr) {
			return nil, errors.New("the display is not on the default graphics adapter")
		}
		var desc outputDesc
		comCall(out, vtOutputGetDesc, uintptr(unsafe.Pointer(&desc))) // #nosec G103 -- COM
		c := desc.Coords
		if int(c.Left) != mon.X || int(c.Top) != mon.Y || int(c.Right-c.Left) != mon.W || int(c.Bottom-c.Top) != mon.H {
			comRelease(&out)
			continue
		}
		if desc.Rotation > 1 { // DXGI_MODE_ROTATION_IDENTITY is 1 (0: unspecified)
			comRelease(&out)
			return nil, errors.New("rotated display")
		}
		var out1 uintptr
		hr = comCall(out, vtQueryInterface, uintptr(unsafe.Pointer(&iidIDXGIOutput1)), uintptr(unsafe.Pointer(&out1))) // #nosec G103 -- COM
		comRelease(&out)
		if failed(hr) {
			return nil, fmt.Errorf("IDXGIOutput1: 0x%x", hr)
		}
		hr = comCall(out1, vtOutput1DuplicateOut, d.dev, uintptr(unsafe.Pointer(&d.dup))) // #nosec G103 -- COM
		comRelease(&out1)
		if failed(hr) {
			return nil, fmt.Errorf("DuplicateOutput: 0x%x", hr)
		}
		break
	}
	td := texture2DDesc{Width: uint32(d.w), Height: uint32(d.h), MipLevels: 1, ArraySize: 1, Format: formatBGRA, SampleCount: 1, // #nosec G115 -- display size
		Usage: usageStaging, CPUAccessFlags: cpuAccessRead}
	if hr := comCall(d.dev, vtDevCreateTexture2D, uintptr(unsafe.Pointer(&td)), 0, uintptr(unsafe.Pointer(&d.staging))); failed(hr) { // #nosec G103 -- COM
		return nil, fmt.Errorf("CreateTexture2D: 0x%x", hr)
	}
	d.clean = make([]byte, d.w*d.h*4)
	ok = true
	return d, nil
}

// next takes the next desktop image if there is one within timeout ms; it
// reports whether the image changed.
func (d *dupl) next(timeout uint32) (bool, error) {
	var info duplFrameInfo
	var res uintptr
	hr := comCall(d.dup, vtDupAcquireNextFrame, uintptr(timeout), uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&res))) // #nosec G103 -- COM
	if hr == dxgiErrWaitTimeout {
		return false, nil
	}
	if failed(hr) {
		return false, fmt.Errorf("AcquireNextFrame: 0x%x", hr) // e.g. access lost: desktop switch, mode change
	}
	defer comCall(d.dup, vtDupReleaseFrame)
	defer comRelease(&res)
	if info.LastPresentTime == 0 && d.have {
		return false, nil // only the pointer moved
	}
	var tex uintptr
	if hr := comCall(res, vtQueryInterface, uintptr(unsafe.Pointer(&iidID3D11Texture2D)), uintptr(unsafe.Pointer(&tex))); failed(hr) { // #nosec G103 -- COM
		return false, fmt.Errorf("frame texture: 0x%x", hr)
	}
	comCall(d.ctx, vtCtxCopyResource, d.staging, tex)
	comRelease(&tex)
	var m mappedSubresource
	if hr := comCall(d.ctx, vtCtxMap, d.staging, 0, mapRead, 0, uintptr(unsafe.Pointer(&m))); failed(hr) { // #nosec G103 -- COM
		return false, fmt.Errorf("mapping the frame: 0x%x", hr)
	}
	row := d.w * 4
	pitch := int(m.RowPitch)
	src := unsafe.Slice((*byte)(ptrOf(m.Data)), pitch*(d.h-1)+row) // #nosec G103 -- mapped texture memory
	for y := 0; y < d.h; y++ {
		copy(d.clean[y*row:(y+1)*row], src[y*pitch:y*pitch+row])
	}
	comCall(d.ctx, vtCtxUnmap, d.staging, 0)
	d.have = true
	return true, nil
}

func (d *dupl) close() {
	comRelease(&d.staging)
	comRelease(&d.dup)
	comRelease(&d.ctx)
	comRelease(&d.dev)
}
