//go:build linux || windows

package agent

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/max-zit/rmmzit/internal/proto"
)

// monitor.check: counts matching events of the Windows event logs and
// tells which processes run.

func init() {
	register(proto.KindMonitorCheck, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a proto.MonitorRun
		if err := args(raw, &a); err != nil {
			return nil, err
		}
		if len(a.Events) > proto.MaxEventMonitors || len(a.Processes) > proto.MaxProcessMonitors {
			return nil, errors.New("too many monitors")
		}
		out := proto.MonitorResults{Events: []proto.EventCount{}, Processes: []proto.ProcessState{}}
		for _, e := range a.Events {
			c := proto.EventCount{Key: e.Key}
			if err := e.Valid(); err != nil {
				c.Error = err.Error()
			} else if n, err := countEvents(ctx, e); err != nil {
				c.Error = err.Error()
			} else {
				c.Count = n
			}
			out.Events = append(out.Events, c)
		}
		if len(a.Processes) > 0 {
			procs, err := processList()
			if err != nil {
				return nil, err
			}
			for _, name := range a.Processes {
				st := proto.ProcessState{Name: name}
				for _, p := range procs {
					if proto.SameProcess(p.Name, name) {
						st.Running = true
						break
					}
				}
				out.Processes = append(out.Processes, st)
			}
		}
		return out, nil
	})
}
