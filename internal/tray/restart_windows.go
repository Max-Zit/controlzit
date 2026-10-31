//go:build windows

package tray

import (
	"os/exec"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/max-zit/rmmzit/internal/agent"
)

// The administrator's policy asks for a restart (updates need one): the
// icon asks the user now and then until the deadline, when the server
// restarts the computer itself.

var pMessageBox = user32.NewProc("MessageBoxW")

const (
	mbYesNo       = 0x4
	mbIconInfo    = 0x40
	mbTopMost     = 0x40000
	mbSetForegrnd = 0x10000
	idYes         = 6

	// restartRemind is how long "Later" postpones the question.
	restartRemind = 4 * time.Hour
)

var restartAsk struct {
	sync.Mutex
	open     bool
	deadline time.Time // of the request last asked about
	asked    time.Time
}

// checkRestart asks for a pending restart when it is time to (tray timer).
func checkRestart() {
	s, err := agent.ReadStatus(st.statusPath)
	if err != nil || s.Restart == nil || s.Restart.Deadline.IsZero() {
		return
	}
	d := s.Restart.Deadline
	restartAsk.Lock()
	defer restartAsk.Unlock()
	if restartAsk.open || (d.Equal(restartAsk.deadline) && time.Since(restartAsk.asked) < restartRemind) {
		return
	}
	restartAsk.open, restartAsk.deadline, restartAsk.asked = true, d, time.Now()
	go askRestart(d)
}

func askRestart(deadline time.Time) {
	defer func() {
		restartAsk.Lock()
		restartAsk.open = false
		restartAsk.Unlock()
	}()
	text := T("Your administrator needs to restart this computer to finish installing updates.") + "\n\n" +
		T("It restarts automatically on %s.", deadline.Local().Format("2006-01-02 15:04")) + "\n\n" +
		T("Restart now? Save your work first. Choose No to be reminded later.")
	r, _, _ := pMessageBox.Call(0, uintptr(unsafe.Pointer(utf16(text))), uintptr(unsafe.Pointer(utf16(T("RMMZit: restart needed")))), // #nosec G103 -- Win32 strings
		mbYesNo|mbIconInfo|mbTopMost|mbSetForegrnd)
	if r != idYes {
		return
	}
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return
	}
	shutdown := filepath.Join(sys, "shutdown.exe")
	_ = exec.Command(shutdown, "/r", "/t", "30", "/c", T("Restarting to finish installing updates.")).Run() // #nosec G204 G702 -- the system program, fixed arguments
}
