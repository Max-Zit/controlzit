//go:build windows

package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ping sends one ICMP echo with the Windows ICMP API (no raw sockets, no
// ping.exe whose output is in the language of the system). IPv4 only.

var (
	iphlpapi        = windows.NewLazySystemDLL("iphlpapi.dll")
	pIcmpCreateFile = iphlpapi.NewProc("IcmpCreateFile")
	pIcmpSendEcho   = iphlpapi.NewProc("IcmpSendEcho")
	pIcmpCloseHndl  = iphlpapi.NewProc("IcmpCloseHandle")
)

func ping(ctx context.Context, host string) (time.Duration, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return 0, fmt.Errorf("cannot resolve %s (IPv4)", host)
	}
	ip4 := ips[0].To4()
	h, _, err := pIcmpCreateFile.Call()
	if h == uintptr(windows.InvalidHandle) {
		return 0, fmt.Errorf("IcmpCreateFile: %w", err)
	}
	defer func() { _, _, _ = pIcmpCloseHndl.Call(h) }()
	data := []byte("RMMZit")
	reply := make([]byte, 128) // ICMP_ECHO_REPLY, the data and room for an ICMP error
	timeout := uint32(netCheckTimeout / time.Millisecond)
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < netCheckTimeout {
			timeout = uint32(max(left, time.Second) / time.Millisecond) // #nosec G115 -- at most 10 s
		}
	}
	n, _, _ := pIcmpSendEcho.Call(h, uintptr(binary.LittleEndian.Uint32(ip4)),
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0, // #nosec G103 -- Win32 buffer
		uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout)) // #nosec G103 -- Win32 buffer
	if n == 0 {
		return 0, errors.New("no answer (timed out)")
	}
	// ICMP_ECHO_REPLY: Address, Status, RoundTripTime (uint32 each).
	if status := binary.LittleEndian.Uint32(reply[4:8]); status != 0 {
		return 0, fmt.Errorf("no answer (ICMP status %d)", status)
	}
	return time.Duration(binary.LittleEndian.Uint32(reply[8:12])) * time.Millisecond, nil
}
