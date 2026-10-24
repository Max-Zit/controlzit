//go:build !windows && !linux

package rd

import (
	"context"
	"errors"
	"log/slog"

	"github.com/coder/websocket"
)

// Serve is not available on this system.
func Serve(ctx context.Context, ws *websocket.Conn, technician string, notice, clipboard bool, log *slog.Logger) error {
	return errors.New("remote desktop is not supported on this system yet")
}
