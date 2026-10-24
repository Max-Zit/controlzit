//go:build windows

package tray

import (
	_ "embed"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/jchv/go-webview2"
	"github.com/max-zit/controlzit/internal/agent"
)

// The "Open ControlZit Agent" window: an overview page rendered with
// WebView2 (part of Windows 10 and 11).

//go:embed ui.html
var uiHTML string

var (
	//go:embed icons/app.ico
	icoApp []byte
	//go:embed icons/connected.ico
	icoConnected []byte
	//go:embed icons/offline.ico
	icoOffline []byte
)

var (
	pLoadImage   = user32.NewProc("LoadImageW")
	pSendMessage = user32.NewProc("SendMessageW")
	pShowWindow  = user32.NewProc("ShowWindow")
	pIsIconic    = user32.NewProc("IsIconic")
	pSysMetrics  = user32.NewProc("GetSystemMetrics")
)

// iconDir is where the icons are written for LoadImage.
func iconDir() string {
	d := filepath.Join(os.Getenv("LOCALAPPDATA"), "ControlZit")
	_ = os.MkdirAll(d, 0o700) // #nosec G703 -- the user's own LOCALAPPDATA
	return d
}

// loadIcon writes an embedded .ico and loads it at the given size.
func loadIcon(name string, data []byte, size int) uintptr {
	p := filepath.Join(iconDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return 0
	}
	const imageIcon, lrLoadFromFile = 1, 0x10
	h, _, _ := pLoadImage.Call(0, uintptr(unsafe.Pointer(utf16(p))), imageIcon, uintptr(size), uintptr(size), lrLoadFromFile) // #nosec G103 G115 -- Win32 string, icon size
	return h
}

func smallIconSize() int {
	n, _, _ := pSysMetrics.Call(49) // SM_CXSMICON
	if n == 0 {
		return 16
	}
	return int(n)
}

// viewStatus is what the page gets: the agent status and whether it is
// fresh (the service writes it at least every minute while it runs).
type viewStatus struct {
	agent.Status
	Running bool `json:"running"`
	Stale   bool `json:"stale"`
}

func currentStatus() viewStatus {
	s, err := agent.ReadStatus(st.statusPath)
	if err != nil {
		return viewStatus{}
	}
	stale := time.Since(s.Updated) > 3*time.Minute
	return viewStatus{Status: s, Running: !stale, Stale: stale}
}

type window struct {
	mu   sync.Mutex
	w    webview2.WebView
	hwnd uintptr
}

var win window

// open shows the window, or brings it to the front.
func (v *window) open() {
	v.mu.Lock()
	if v.w != nil {
		h := v.hwnd
		v.mu.Unlock()
		if r, _, _ := pIsIconic.Call(h); r != 0 {
			_, _, _ = pShowWindow.Call(h, 9) // SW_RESTORE
		}
		_, _, _ = pSetForeground.Call(h)
		return
	}
	v.mu.Unlock()
	go v.run()
}

func (v *window) run() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		DataPath:  filepath.Join(iconDir(), "WebView"),
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title: "ControlZit Agent", Width: 760, Height: 420, Center: true,
		},
	})
	if w == nil {
		return // no WebView2 runtime: the menu still shows the state
	}
	hwnd := uintptr(w.Window())
	const wmSetIcon = 0x0080
	if h := loadIcon("app-16.ico", icoApp, 16); h != 0 {
		_, _, _ = pSendMessage.Call(hwnd, wmSetIcon, 0, h)
	}
	if h := loadIcon("app-32.ico", icoApp, 32); h != 0 {
		_, _, _ = pSendMessage.Call(hwnd, wmSetIcon, 1, h)
	}
	w.SetSize(620, 380, webview2.HintMin)
	_ = w.Bind("czStatus", func() viewStatus { return currentStatus() })
	w.SetHtml(uiHTML)
	v.mu.Lock()
	v.w, v.hwnd = w, hwnd
	v.mu.Unlock()
	w.Run()
	v.mu.Lock()
	v.w, v.hwnd = nil, 0
	v.mu.Unlock()
	w.Destroy()
}
