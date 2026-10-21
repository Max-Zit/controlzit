package web

import (
	"context"
	"time"
)

// CallForTest sends a command without arguments (tests).
func (s *Server) CallForTest(ctx context.Context, deviceID int64, kind string) error {
	return s.call(ctx, deviceID, "test", kind, nil, nil, 10*time.Second)
}
