//go:build linux || windows

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/coder/websocket"

	"github.com/max-zit/controlzit/internal/proto"
)

// A terminal is an administrator's shell (root on Linux, SYSTEM on Windows)
// on a pseudo-terminal. The agent runs with those rights already, so it
// needs no helper process: it connects the stream itself and copies between
// the stream and the terminal.

// terminal is a running shell on a pseudo-terminal (term_linux.go,
// term_windows.go).
type terminal interface {
	Read(p []byte) (int, error) // shell output; an error once it is gone
	Write(p []byte) (int, error)
	Resize(cols, rows int)
	Wait() int // waits for the shell, returns its exit code
	Hangup()   // asks the shell and what it started to end
	Kill()     // ends them at once
	Close()    // releases the terminal after Wait
}

func init() {
	register(proto.KindTermStart, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a proto.TermStart
		if err := args(raw, &a); err != nil {
			return nil, err
		}
		if a.Session == "" || a.Token == "" || len(a.Session) > 64 || len(a.Technician) > 120 || !proto.ValidTermSize(a.Cols, a.Rows) {
			return nil, errors.New("bad terminal request")
		}
		ws, err := dialStream(ctx, helperDir, a.Session, a.Token)
		if err != nil {
			return nil, err
		}
		t, err := startTerminal(a)
		if err != nil {
			_ = ws.Close(websocket.StatusInternalError, "")
			return nil, fmt.Errorf("cannot start the shell: %w", err)
		}
		if self != nil {
			self.Log.Info("terminal session started", "session", a.Session, "technician", a.Technician)
		}
		go serveTerminal(ws, t, a.Session)
		return nil, nil
	})
}

func serveTerminal(ws *websocket.Conn, t terminal, session string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exited := make(chan int, 1)
	go func() { exited <- t.Wait() }()
	// shell → browser
	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		buf := make([]byte, 32<<10)
		for {
			n, err := t.Read(buf)
			if n > 0 {
				wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
				werr := ws.Write(wctx, websocket.MessageBinary, buf[:n])
				wcancel()
				if werr != nil {
					cancel()
					return
				}
			}
			if err != nil {
				return // once the shell and its children are gone
			}
		}
	}()
	// browser → shell
	go func() {
		for {
			typ, data, err := ws.Read(ctx)
			if err != nil {
				cancel()
				return
			}
			if typ != websocket.MessageText {
				continue
			}
			var in proto.TermInput
			if json.Unmarshal(data, &in) != nil {
				continue
			}
			switch in.T {
			case "i":
				if _, err := t.Write([]byte(in.D)); err != nil {
					cancel()
					return
				}
			case "r":
				if proto.ValidTermSize(in.Cols, in.Rows) {
					t.Resize(in.Cols, in.Rows)
				}
			}
		}
	}()
	code := -1
	select {
	case code = <-exited:
		// Let the last output through, then say so.
		select {
		case <-outDone:
		case <-time.After(time.Second):
		}
		wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
		_ = ws.Write(wctx, websocket.MessageText, []byte(`{"t":"exit","code":`+strconv.Itoa(code)+`}`))
		wcancel()
		_ = ws.Close(websocket.StatusNormalClosure, "")
	case <-ctx.Done():
		// The technician left: hang up the shell and what it started.
		t.Hangup()
		select {
		case code = <-exited:
		case <-time.After(3 * time.Second):
			t.Kill()
			code = <-exited
		}
		_ = ws.CloseNow()
	}
	t.Close()
	if self != nil {
		self.Log.Info("terminal session ended", "session", session, "exit", code)
	}
}
