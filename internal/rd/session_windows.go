//go:build windows

package rd

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/max-zit/rmmzit/internal/proto"
)

// Pacing: at most this many frames per second, and at most maxInFlight
// tile batches the browser has not acknowledged yet (adapts to bandwidth).
const (
	frameInterval = 40 * time.Millisecond
	maxInFlight   = 2
)

// Serve streams the screen over ws and replays the input it receives,
// until the connection ends. Unless the console setting switched it off, it
// shows the notice while connected.
func Serve(ctx context.Context, ws *websocket.Conn, technician string, notice, clipboard bool, log *slog.Logger) error {
	setDPIAware()
	if notice {
		banner := ShowBanner("RMMZit: " + technician + " is connected to this computer")
		defer banner.Close()
		if banner.hwnd == 0 {
			log.Error("the on-screen notice could not be shown", "err", banner.Err)
		} else {
			log.Info("on-screen notice shown", "warnings", banner.Err)
		}
	} else {
		log.Info("on-screen notice switched off in the console settings")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Clipboard: text copied on the remote computer goes to the browser;
	// the browser sets the remote clipboard before the technician pastes.
	// Copied files are offered to the browser for download, and files the
	// technician pastes are put on the clipboard as copied files.
	reply := func(r proto.RDReply) {
		b, _ := json.Marshal(r)
		wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
		defer wcancel()
		_ = ws.Write(wctx, websocket.MessageText, b)
	}
	var clip *Clipboard
	if clipboard {
		copied := func(paths []string) {
			if InStage(paths) {
				return // the files the technician just pasted
			}
			reply(proto.RDReply{T: "copied", Items: FileItems(paths)})
		}
		// Copied files are only visible to the user's own processes.
		watching, err := startFileWatcher(ctx, copied)
		if err != nil {
			log.Warn("copied files cannot be watched", "err", err)
		}
		inProcess := copied
		if watching {
			inProcess = nil
		}
		clip, err = StartClipboard(ctx, func(text string) {
			wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
			defer wcancel()
			_ = ws.Write(wctx, websocket.MessageBinary, append([]byte{proto.RDClip}, text...))
		}, inProcess)
		if err != nil {
			log.Warn("clipboard not available", "err", err)
		}
	}
	inputs := make(chan proto.RDInput, 256)
	var credits atomic.Int32
	credits.Store(maxInFlight)
	var quality atomic.Int32
	quality.Store(65)
	readErr := make(chan error, 1)
	go func() {
		for {
			typ, data, err := ws.Read(ctx)
			if err != nil {
				readErr <- err
				return
			}
			if typ != websocket.MessageText {
				continue
			}
			var in proto.RDInput
			if json.Unmarshal(data, &in) != nil {
				continue
			}
			switch in.T {
			case "ack":
				if credits.Add(1) > maxInFlight {
					credits.Store(maxInFlight)
				}
			case "q":
				if in.Quality >= 10 && in.Quality <= 95 {
					quality.Store(int32(in.Quality)) // #nosec G115 -- 10..95
				}
			case "clip":
				if clip != nil && len(in.Text) <= proto.MaxClipboard {
					if err := clip.Set(in.Text); err != nil {
						log.Warn("cannot set the remote clipboard", "err", err)
					}
				}
			case "stage":
				if clip == nil {
					reply(proto.RDReply{T: "error", For: "stage", Text: "the clipboard exchange is switched off in the settings"})
					break
				}
				dir, err := StageDir()
				if err != nil {
					reply(proto.RDReply{T: "error", For: "stage", Text: err.Error()})
					break
				}
				reply(proto.RDReply{T: "stage", Path: dir})
			case "files":
				if clip == nil || !InStage(in.Paths) {
					reply(proto.RDReply{T: "error", For: "files", Text: "these files cannot be put on the clipboard"})
					break
				}
				if err := clip.SetFiles(in.Paths); err != nil {
					reply(proto.RDReply{T: "error", For: "files", Text: err.Error()})
					break
				}
				log.Info("files put on the remote clipboard", "count", len(in.Paths))
				reply(proto.RDReply{T: "files"})
			case "full":
				select {
				case inputs <- in:
				default:
				}
			default:
				select {
				case inputs <- in:
				default: // drop input when the desktop thread is busy
				}
			}
		}
	}()

	done := make(chan error, 1)
	go func() { done <- desktopLoop(ctx, ws, inputs, &credits, &quality, log) }()
	select {
	case err := <-readErr:
		cancel()
		<-done
		if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
			return nil
		}
		return err
	case err := <-done:
		return err
	}
}

// desktopLoop runs on one locked thread: capture and input injection must
// happen on the thread attached to the input desktop.
func desktopLoop(ctx context.Context, ws *websocket.Conn, inputs <-chan proto.RDInput, credits, quality *atomic.Int32, log *slog.Logger) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var c Capturer
	defer c.Close()
	c.Monitor = 0 // the primary display; the browser can choose another or all
	sendInfo := false
	var inj Injector
	defer inj.ReleaseAll()
	enc := &Encoder{}
	tick := time.NewTicker(frameInterval)
	defer tick.Stop()
	w, h := 0, 0
	write := func(b []byte, binary bool) error {
		wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		t := websocket.MessageText
		if binary {
			t = websocket.MessageBinary
		}
		return ws.Write(wctx, t, b)
	}
	failures := 0
	method := ""
	var lastDXErr error
	for {
		select {
		case <-ctx.Done():
			return nil
		case in := <-inputs:
			switch in.T {
			case "m":
				vx, vy, vw, vh := c.ToVirtual(in.X, in.Y)
				_ = inj.Mouse(vx, vy, in.Buttons, in.Wheel, vw, vh)
			case "k":
				_ = inj.Key(in.Code, in.Down)
			case "text":
				if len(in.Text) <= 4096 {
					_ = inj.Type(in.Text)
				}
			case "cad":
				if err := CtrlAltDel(); err != nil {
					log.Warn("Ctrl+Alt+Del failed", "err", err)
				}
			case "mon":
				c.Monitor = in.Monitor
				enc.Reset()
				sendInfo = true
			case "full":
				enc.Reset()
			}
		case <-tick.C:
			if credits.Load() <= 0 {
				continue
			}
			f, changed, err := c.Capture()
			if err != nil {
				failures++
				if failures == 1 || failures%100 == 0 {
					log.Warn("screen capture failed", "err", err)
				}
				if failures > 600 {
					return errors.New("screen capture keeps failing: " + err.Error())
				}
				continue
			}
			failures = 0
			if m := map[bool]string{true: "desktop duplication", false: "GDI"}[c.UsingDXGI()]; m != method {
				method = m
				log.Info("screen capture", "method", m, "desktop", c.Desktop())
			}
			if e := c.DXError(); e != nil && e != lastDXErr {
				lastDXErr = e
				log.Info("desktop duplication not used", "reason", e.Error())
			}
			if changed || sendInfo || f.W != w || f.H != h {
				sendInfo = false
				w, h = f.W, f.H
				enc.Reset()
				info, _ := json.Marshal(proto.RDScreenInfo{Width: f.W, Height: f.H, Desktop: c.Desktop(), Monitors: c.Monitors(), Monitor: c.Shown()})
				if err := write(append([]byte{proto.RDScreen}, info...), true); err != nil {
					return err
				}
			}
			enc.Quality = int(quality.Load())
			tiles, err := enc.Encode(f)
			if err != nil {
				return err
			}
			if len(tiles) == 0 {
				continue
			}
			credits.Add(-1)
			if err := write(proto.EncodeTiles(tiles), true); err != nil {
				return err
			}
		}
	}
}
