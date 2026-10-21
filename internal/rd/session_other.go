//go:build !windows

package rd

import (
	"context"
	"errors"
	"log/slog"

	"github.com/coder/websocket"
)

// Serve is not available outside Windows yet.
func Serve(ctx context.Context, ws *websocket.Conn, technician string, log *slog.Logger) error {
	return errors.New("remote desktop is not supported on this system yet")
}
