package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/max-zit/controlzit/internal/proto"
)

// handler runs one kind of command.
type handler func(ctx context.Context, args json.RawMessage) (any, error)

var handlers = map[string]handler{}

// register adds a command kind (from init functions of the feature files).
func register(kind string, h handler) { handlers[kind] = h }

// SetHandler replaces the handler of a command kind and returns the old one
// (tests of the server, before the agent starts).
func SetHandler(kind string, h func(context.Context, json.RawMessage) (any, error)) func(context.Context, json.RawMessage) (any, error) {
	old := handlers[kind]
	handlers[kind] = h
	return old
}

// replay remembers the IDs of accepted commands until they expire.
type replay struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (r *replay) first(id string, until time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for k, t := range r.seen {
		if now.After(t) {
			delete(r.seen, k)
		}
	}
	if _, ok := r.seen[id]; ok {
		return false
	}
	r.seen[id] = until
	return true
}

var seenCommands = &replay{seen: map[string]time.Time{}}

// learnCommandKey stores the server's command key for agents enrolled
// before command signing existed (sent over the pinned TLS channel). A
// different key than the stored one is refused: rotating the key will be a
// signed operation of its own.
func (a *Agent) learnCommandKey(k []byte) {
	if len(k) != ed25519.PublicKeySize {
		return
	}
	if len(a.Cfg.CommandKey) == 0 {
		a.Cfg.CommandKey = k
		if err := a.Cfg.Save(a.Dir); err != nil {
			a.Log.Error("cannot save the command key", "err", err)
			return
		}
		a.Log.Info("server command key stored")
		return
	}
	if !bytes.Equal(a.Cfg.CommandKey, k) {
		a.Log.Error("the server announced a different command key; commands are refused until the agent is enrolled again")
	}
}

// runCommand verifies a command, runs it and sends the result.
func (a *Agent) runCommand(ctx context.Context, ws *websocket.Conn, sc proto.SignedCommand) {
	res := proto.Result{}
	cmd, err := proto.Verify(ed25519.PublicKey(a.Cfg.CommandKey), sc, a.Cfg.AgentID, time.Now())
	if err != nil {
		// Answer with the ID if it can be read, so the server does not wait.
		var c proto.Command
		if json.Unmarshal(sc.Command, &c) == nil {
			res.ID = c.ID
		}
		a.Log.Warn("command refused", "err", err)
		res.Error = "refused by the agent: " + err.Error()
		_ = sendMsg(ctx, ws, proto.TypeResult, res)
		return
	}
	res.ID = cmd.ID
	if !seenCommands.first(cmd.ID, cmd.Expires.Add(proto.MaxCommandAge)) {
		a.Log.Warn("replayed command refused", "id", cmd.ID)
		res.Error = "refused by the agent: command already run"
		_ = sendMsg(ctx, ws, proto.TypeResult, res)
		return
	}
	h := handlers[cmd.Kind]
	if h == nil {
		res.Error = fmt.Sprintf("this agent (version %s) does not know the command %q", Version, cmd.Kind)
		_ = sendMsg(ctx, ws, proto.TypeResult, res)
		return
	}
	if cmd.Kind != proto.KindFSRead && cmd.Kind != proto.KindFSWrite {
		a.Log.Info("command", "kind", cmd.Kind, "by", cmd.Issuer, "args", trim(redact(cmd.Args), 300))
	}
	cctx, cancel := context.WithDeadline(ctx, cmd.Expires.Add(proto.MaxCommandAge))
	defer cancel()
	runningCommands.add(cmd.ID, cancel)
	defer runningCommands.remove(cmd.ID)
	out, err := h(cctx, cmd.Args)
	if err != nil {
		res.Error = err.Error()
	} else if out != nil {
		if res.Data, err = json.Marshal(out); err != nil {
			res.Error = err.Error()
		}
	}
	if err := sendMsg(ctx, ws, proto.TypeResult, res); err != nil {
		a.Log.Warn("cannot send a command result", "err", err)
	}
}

// args decodes command arguments strictly.
func args(raw json.RawMessage, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return errors.New("bad command arguments: " + err.Error())
	}
	return nil
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// redact hides secrets (session tokens) in logged command arguments.
func redact(raw json.RawMessage) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return string(raw)
	}
	for k := range m {
		if k == "token" || k == "password" || k == "data" {
			m[k] = "***"
		}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// runningCommands are the commands in progress, so the server can stop one
// (a task cancelled in the console).
var runningCommands = &cmdSet{m: map[string]context.CancelFunc{}}

type cmdSet struct {
	mu sync.Mutex
	m  map[string]context.CancelFunc
}

func (c *cmdSet) add(id string, cancel context.CancelFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[id] = cancel
}

func (c *cmdSet) remove(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, id)
}

func (c *cmdSet) cancel(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f := c.m[id]; f != nil {
		f()
		return true
	}
	return false
}

func init() {
	register(proto.KindCancel, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a proto.Cancel
		if err := args(raw, &a); err != nil {
			return nil, err
		}
		return map[string]bool{"stopped": runningCommands.cancel(a.ID)}, nil
	})
}
