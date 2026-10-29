//go:build windows

package agent

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/max-zit/controlzit/internal/proto"
)

// Events are counted with the Windows Event Log API (an XPath query of the
// log, each event handle closed again), without PowerShell.

var (
	wevtapi      = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery = wevtapi.NewProc("EvtQuery")
	procEvtNext  = wevtapi.NewProc("EvtNext")
	procEvtClose = wevtapi.NewProc("EvtClose")
)

const (
	evtQueryChannelPath         = 0x1
	evtQueryTolerateQueryErrors = 0x1000
	eventCountCap               = 100000
)

// processList is the process list for the monitors.
func processList() ([]proto.Process, error) { return listProcesses() }

// eventQuery writes the XPath filter of a monitor.
func eventQuery(e proto.EventMonitor) string {
	conds := []string{"TimeCreated[timediff(@SystemTime) <= " + strconv.Itoa(e.Minutes*60000) + "]"}
	if len(e.IDs) > 0 {
		ids := make([]string, len(e.IDs))
		for i, id := range e.IDs {
			ids[i] = "EventID=" + strconv.Itoa(id)
		}
		conds = append(conds, "("+strings.Join(ids, " or ")+")")
	}
	if e.Level > 0 {
		lv := make([]string, e.Level)
		for i := range lv {
			lv[i] = "Level=" + strconv.Itoa(i+1)
		}
		conds = append(conds, "("+strings.Join(lv, " or ")+")")
	}
	if e.Source != "" {
		conds = append(conds, "Provider[@Name='"+e.Source+"']") // Valid refuses quotes and brackets
	}
	return "*[System[" + strings.Join(conds, " and ") + "]]"
}

func countEvents(ctx context.Context, e proto.EventMonitor) (int, error) {
	if err := procEvtQuery.Find(); err != nil {
		return 0, errors.New("this Windows has no event log API")
	}
	path, err := windows.UTF16PtrFromString(e.Log)
	if err != nil {
		return 0, err
	}
	query, err := windows.UTF16PtrFromString(eventQuery(e))
	if err != nil {
		return 0, err
	}
	rs, _, qerr := procEvtQuery.Call(0, uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(query)), evtQueryChannelPath|evtQueryTolerateQueryErrors) // #nosec G103 -- Win32 strings
	if rs == 0 {
		return 0, errors.New("cannot read the " + e.Log + " log: " + qerr.Error())
	}
	defer procEvtClose.Call(rs) //nolint:errcheck
	var handles [256]uintptr
	count := 0
	for count < eventCountCap {
		if ctx.Err() != nil {
			return count, ctx.Err()
		}
		var got uint32
		ok, _, nerr := procEvtNext.Call(rs, uintptr(len(handles)), uintptr(unsafe.Pointer(&handles[0])), 5000, 0, uintptr(unsafe.Pointer(&got))) // #nosec G103 -- Win32 out-parameters
		if ok == 0 {
			if errors.Is(nerr, windows.ERROR_NO_MORE_ITEMS) {
				return count, nil
			}
			return count, errors.New("reading the " + e.Log + " log: " + nerr.Error())
		}
		for i := uint32(0); i < got; i++ {
			_, _, _ = procEvtClose.Call(handles[i])
		}
		count += int(got)
	}
	return count, nil
}
