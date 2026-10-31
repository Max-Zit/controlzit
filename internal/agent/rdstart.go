package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/rd"
)

// The service cannot see the desktop (it runs in session 0), so rd.start
// launches a helper process — this same program with the rdhelper command —
// in the console session. The helper connects its own stream to the server.

// Linux desktops the remote desktop cannot use.
var (
	errWayland = errors.New("remote desktop is not possible: the desktop of this computer runs on Wayland, which does not let a background service see the screen or control it. Sign in with an X11 (Xorg) session, or use the Terminal")
	errNoX     = errors.New("no graphical desktop is running on this computer: use the Terminal")
)

// helperDir is the data directory passed to helpers (set by Run).
var helperDir string

func init() {
	register(proto.KindRDStart, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a proto.RDStart
		if err := args(raw, &a); err != nil {
			return nil, err
		}
		if a.Session == "" || a.Token == "" || len(a.Session) > 64 || len(a.Technician) > 120 {
			return nil, errors.New("bad remote desktop request")
		}
		if err := startHelper(helperDir, a); err != nil {
			if errors.Is(err, errWayland) || errors.Is(err, errNoX) {
				return nil, err // the console translates these
			}
			return nil, fmt.Errorf("cannot start the remote desktop helper: %w", err)
		}
		return nil, nil
	})
}

// RunHelper is the rdhelper command: it reads the session token from
// stdin, connects the stream and serves the desktop.
func RunHelper(ctx context.Context, dir, session, technician, token string, notice, clipboard bool, log *slog.Logger) error {
	ws, err := dialStream(ctx, dir, session, token)
	if err != nil {
		return err
	}
	defer ws.CloseNow()
	log.Info("remote desktop session started", "session", session, "technician", technician)
	err = rd.Serve(ctx, ws, technician, notice, clipboard, log)
	log.Info("remote desktop session ended", "session", session, "err", err)
	return err
}

// dialStream connects a session stream to the server with this device's
// TLS identity and the session token.
func dialStream(ctx context.Context, dir, session, token string) (*websocket.Conn, error) {
	cfg, err := LoadConfig(dir)
	if err != nil {
		return nil, err
	}
	key, err := LoadOrCreateKey(dir)
	if err != nil {
		return nil, err
	}
	cert, err := clientCert(key)
	if err != nil {
		return nil, err
	}
	hc := httpClient(pinnedTLS(cfg.Fingerprint, cert))
	hc.Timeout = 0
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(dctx, cfg.ServerURL+proto.PathStream+"?session="+url.QueryEscape(session), &websocket.DialOptions{
		HTTPClient: hc,
		HTTPHeader: http.Header{"User-Agent": {"rmmzit-agent/" + Version}, "X-Cz-Session-Token": {strings.TrimSpace(token)}},
	})
	if err != nil {
		return nil, fmt.Errorf("stream: %w", err)
	}
	ws.SetReadLimit(1 << 20)
	return ws, nil
}
