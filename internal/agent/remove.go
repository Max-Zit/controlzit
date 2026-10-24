package agent

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
)

// The device was deleted in the console: the agent uninstalls itself (and,
// through Forget, gives Windows Update its own settings back). Only the
// installed service does; the uninstaller starts a few seconds later so the
// answer reaches the server first.
func init() {
	register(proto.KindAgentRemove, func(context.Context, json.RawMessage) (any, error) {
		if !installedService() {
			return nil, errors.New("the agent is not running as the installed service")
		}
		time.AfterFunc(2*time.Second, func() {
			if err := startUninstall(); err != nil && self != nil {
				self.Log.Error("cannot start the uninstall", "err", err)
			}
		})
		return map[string]bool{"started": true}, nil
	})
}
