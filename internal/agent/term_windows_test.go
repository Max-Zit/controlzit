//go:build windows

package agent

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
)

// A PowerShell on a pseudo console answers a command; ending the session
// ends the shell.
func TestWindowsTerminal(t *testing.T) {
	sh, err := startTerminal(proto.TermStart{Session: "s", Token: "t", Technician: "tester", Cols: 100, Rows: 30})
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan []byte, 64)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := sh.Read(buf)
			if n > 0 {
				out <- append([]byte(nil), buf[:n]...)
			}
			if err != nil {
				close(out)
				return
			}
		}
	}()
	sh.Resize(120, 40)
	if _, err := sh.Write([]byte("Write-Output (\"cz\" + \"term \" + $env:RMMZIT_TECHNICIAN)\r")); err != nil {
		t.Fatal(err)
	}
	var seen bytes.Buffer
	deadline := time.After(30 * time.Second)
	for !strings.Contains(seen.String(), "czterm tester") {
		select {
		case b, ok := <-out:
			if !ok {
				t.Fatalf("output ended: %q", seen.String())
			}
			seen.Write(b)
		case <-deadline:
			t.Fatalf("no answer: %q", seen.String())
		}
	}
	done := make(chan int, 1)
	go func() { done <- sh.Wait() }()
	sh.Hangup()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the shell did not end")
	}
	sh.Close()
}
