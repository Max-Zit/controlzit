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

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/rd"
)

// The service cannot see the desktop (it runs in session 0), so rd.start
// launches a helper process — this same program with the rdhelper command —
// in the console session. The helper connects its own stream to the server.

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
			return nil, fmt.Errorf("cannot start the remote desktop helper: %w", err)
		}
		return nil, nil
	})
}

// RunHelper is the rdhelper command: it reads the session token from
// stdin, connects the stream and serves the desktop.
func RunHelper(ctx context.Context, dir, session, technician, token string, notice bool, log *slog.Logger) error {
	cfg, err := LoadConfig(dir)
	if err != nil {
		return err
	}
	key, err := LoadOrCreateKey(dir)
	if err != nil {
		return err
	}
	cert, err := clientCert(key)
	if err != nil {
		return err
	}
	hc := httpClient(pinnedTLS(cfg.Fingerprint, cert))
	hc.Timeout = 0
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	ws, _, err := websocket.Dial(dctx, cfg.ServerURL+proto.PathStream+"?session="+url.QueryEscape(session), &websocket.DialOptions{
		HTTPClient: hc,
		HTTPHeader: http.Header{"User-Agent": {"controlzit-agent/" + Version}, "X-Cz-Session-Token": {strings.TrimSpace(token)}},
	})
	cancel()
	if err != nil {
		return fmt.Errorf("stream: %w", err)
	}
	defer ws.CloseNow()
	ws.SetReadLimit(1 << 20)
	log.Info("remote desktop session started", "session", session, "technician", technician)
	err = rd.Serve(ctx, ws, technician, notice, log)
	log.Info("remote desktop session ended", "session", session, "err", err)
	return err
}
