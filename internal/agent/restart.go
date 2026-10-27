package agent

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/max-zit/controlzit/internal/proto"
)

// A policy's restart request goes into the status file, where the tray icon
// of the signed-in user finds it and asks for the restart.
func init() {
	register(proto.KindRestartNotice, func(_ context.Context, raw json.RawMessage) (any, error) {
		var n proto.RestartNotice
		if err := json.Unmarshal(raw, &n); err != nil {
			return nil, err
		}
		if self == nil {
			return nil, errors.New("the agent is not running")
		}
		statusMu.Lock()
		if n.Deadline.IsZero() {
			self.status.Restart = nil
		} else {
			self.status.Restart = &n
		}
		connected := self.status.Connected
		statusMu.Unlock()
		self.publishStatus(connected)
		return nil, nil
	})
}
