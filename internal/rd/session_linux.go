//go:build linux

package rd

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/max-zit/controlzit/internal/proto"
)

// X11 reads the whole screen per frame, so it paces a little slower than
// Windows.
const (
	frameInterval = 66 * time.Millisecond
	maxInFlight   = 2
)

// Serve streams the X11 screen over ws and replays the input it receives,
// until the connection ends. The clipboard is not exchanged on Linux yet.
func Serve(ctx context.Context, ws *websocket.Conn, technician string, notice, _ bool, log *slog.Logger) error {
	d, err := openX()
	if err != nil {
		return errors.New("cannot open the X11 desktop: " + err.Error())
	}
	defer d.Close()
	if notice {
		b, err := showXBanner("ControlZit: " + technician + " is connected to this computer")
		if err != nil {
			log.Error("the on-screen notice could not be shown", "err", err)
		}
		defer b.Close()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
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
			case "stage", "files":
				b, _ := json.Marshal(proto.RDReply{T: "error", For: in.T, Text: "copying files through the clipboard works with Windows computers"})
				wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
				_ = ws.Write(wctx, websocket.MessageText, b)
				wcancel()
			default:
				select {
				case inputs <- in:
				default:
				}
			}
		}
	}()
	done := make(chan error, 1)
	go func() { done <- xLoop(ctx, ws, d, inputs, &credits, &quality, log) }()
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

func xLoop(ctx context.Context, ws *websocket.Conn, d *xDesktop, inputs <-chan proto.RDInput, credits, quality *atomic.Int32, log *slog.Logger) error {
	defer d.ReleaseAll()
	enc := &Encoder{}
	tick := time.NewTicker(frameInterval)
	defer tick.Stop()
	write := func(b []byte) error {
		wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return ws.Write(wctx, websocket.MessageBinary, b)
	}
	w, h, failures := 0, 0, 0
	shm := true
	for {
		select {
		case <-ctx.Done():
			return nil
		case in := <-inputs:
			switch in.T {
			case "m":
				d.Mouse(in.X, in.Y, in.Buttons, in.Wheel)
			case "k":
				d.Key(in.Code, in.Down)
			case "text":
				if len(in.Text) <= 4096 {
					d.Type(in.Text)
				}
			case "full":
				enc.Reset()
			}
		case <-tick.C:
			if credits.Load() <= 0 {
				continue
			}
			f, err := d.Capture()
			if err != nil {
				failures++
				if failures == 1 || failures%100 == 0 {
					log.Warn("screen capture failed", "err", err)
				}
				if failures > 300 {
					return errors.New("screen capture keeps failing: " + err.Error())
				}
				continue
			}
			failures = 0
			if d.shmOK != shm || w == 0 {
				shm = d.shmOK
				log.Info("screen capture", "method", map[bool]string{true: "X11 shared memory", false: "X11 GetImage"}[shm], "width", f.W, "height", f.H, "shm", errText(d.shmErr))
			}
			if f.W != w || f.H != h {
				w, h = f.W, f.H
				enc.Reset()
				info, _ := json.Marshal(proto.RDScreenInfo{Width: f.W, Height: f.H, Desktop: "Default", Monitor: -1})
				if err := write(append([]byte{proto.RDScreen}, info...)); err != nil {
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
			if err := write(proto.EncodeTiles(tiles)); err != nil {
				return err
			}
		}
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
