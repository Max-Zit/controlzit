package web

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/max-zit/controlzit/internal/auth"
	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

// Agent channel timing.
const (
	heartbeatSeconds = 60
	inventoryHours   = 12
	// An agent that sent nothing for this long is dropped.
	agentReadTimeout = 3 * heartbeatSeconds * time.Second
	// The server pings each agent this often; a channel whose pong does not
	// come within pingTimeout is closed, so a lost agent shows offline in
	// under a minute instead of after agentReadTimeout.
	pingEvery   = 30 * time.Second
	pingTimeout = 15 * time.Second
)

// keepAlive pings ws until ctx ends and closes it when a pong is missing.
// The pongs are read by the connection's read loop.
func keepAlive(ctx context.Context, ws *websocket.Conn) {
	t := time.NewTicker(pingEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pctx, cancel := context.WithTimeout(ctx, pingTimeout)
		err := ws.Ping(pctx)
		cancel()
		if err != nil && ctx.Err() == nil {
			_ = ws.CloseNow()
			return
		}
	}
}

// hub keeps the open agent channels.
type hub struct {
	mu    sync.Mutex
	conns map[int64]*agentConn
}

type agentConn struct {
	deviceID int64
	agentID  string
	ws       *websocket.Conn
	cancel   context.CancelFunc

	mu      sync.Mutex
	pending map[string]chan proto.Result
}

// ErrOffline is returned for commands to a device without a channel.
var ErrOffline = errors.New("the device is offline")

// call sends a signed command and waits for its result.
func (s *Server) call(ctx context.Context, deviceID int64, issuer, kind string, args, out any, timeout time.Duration) error {
	c := s.hub.get(deviceID)
	if c == nil {
		return ErrOffline
	}
	if s.CommandKey == nil {
		return errors.New("the server has no command key")
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return err
	}
	now := s.now()
	cmd := proto.Command{ID: auth.RandomToken(12), AgentID: c.agentID, Kind: kind, Args: raw, IssuedAt: now, Expires: now.Add(timeout), Issuer: issuer}
	sc, err := proto.Sign(s.CommandKey, cmd)
	if err != nil {
		return err
	}
	ch := make(chan proto.Result, 1)
	c.mu.Lock()
	c.pending[cmd.ID] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, cmd.ID)
		c.mu.Unlock()
	}()
	if err := send(ctx, c.ws, proto.TypeCommand, sc); err != nil {
		return ErrOffline
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case res := <-ch:
		if res.Error != "" {
			return &AgentError{Msg: res.Error}
		}
		if out != nil && len(res.Data) > 0 {
			return json.Unmarshal(res.Data, out)
		}
		return nil
	case <-tctx.Done():
		if errors.Is(context.Cause(ctx), errTaskCancelled) {
			// The task was cancelled: the agent stops the command too.
			go s.cancelCommand(deviceID, issuer, cmd.ID) // #nosec G118 -- outlives the cancelled call; own timeout
			return context.Cause(ctx)
		}
		if s.hub.get(deviceID) != c {
			return ErrOffline
		}
		return errors.New("the device did not answer in time")
	}
}

// cancelCommand asks an agent to stop a command it still runs.
func (s *Server) cancelCommand(deviceID int64, issuer, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()
	if err := s.call(ctx, deviceID, issuer, proto.KindCancel, proto.Cancel{ID: id}, nil, actionTimeout); err != nil {
		s.log.Warn("cannot stop a command on the agent", "device", deviceID, "err", err)
	}
}

// AgentError is an error reported by the agent (file not found, access denied …).
type AgentError struct{ Msg string }

func (e *AgentError) Error() string { return e.Msg }

func (c *agentConn) deliver(res proto.Result) {
	c.mu.Lock()
	ch := c.pending[res.ID]
	c.mu.Unlock()
	if ch != nil {
		select {
		case ch <- res:
		default:
		}
	}
}

func newHub() *hub { return &hub{conns: map[int64]*agentConn{}} }

// add registers a channel and closes an older one of the same device.
func (h *hub) add(c *agentConn) {
	h.mu.Lock()
	old := h.conns[c.deviceID]
	h.conns[c.deviceID] = c
	h.mu.Unlock()
	if old != nil {
		old.cancel()
		_ = old.ws.Close(websocket.StatusPolicyViolation, "replaced by a newer connection")
	}
}

// remove forgets the channel if it is still the current one.
func (h *hub) remove(c *agentConn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conns[c.deviceID] == c {
		delete(h.conns, c.deviceID)
		return true
	}
	return false
}

func (h *hub) get(id int64) *agentConn {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conns[id]
}

// Connected reports whether a device has an open channel.
func (s *Server) Connected(id int64) bool { return s.hub.get(id) != nil }

// disconnect closes the channel of a device (it was deleted).
func (s *Server) disconnect(id int64) {
	if c := s.hub.get(id); c != nil {
		c.cancel()
		_ = c.ws.Close(websocket.StatusPolicyViolation, "device removed")
	}
}

func send(ctx context.Context, ws *websocket.Conn, typ string, v any) error {
	env := proto.Envelope{Type: typ}
	if v != nil {
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		env.Data = raw
	}
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return ws.Write(wctx, websocket.MessageText, b)
}

// requestInventory asks a connected agent for a fresh inventory.
func (s *Server) requestInventory(ctx context.Context, id int64) bool {
	c := s.hub.get(id)
	return c != nil && send(ctx, c.ws, proto.TypeInventoryRequest, nil) == nil
}

func agentError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(proto.Error{Error: msg})
}

// peerKey is the ed25519 key of the agent's TLS client certificate. The
// TLS handshake proved that the agent holds the private key.
func peerKey(r *http.Request) ed25519.PublicKey {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	k, _ := r.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	return k
}

func (s *Server) handleAgentEnroll(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if until := s.guard.blocked(r.Context(), ip); !until.IsZero() {
		agentError(w, http.StatusTooManyRequests, "too many failed enrollments from this address")
		return
	}
	pub := peerKey(r)
	if pub == nil {
		agentError(w, http.StatusUnauthorized, "an ed25519 client certificate is required")
		return
	}
	var req proto.EnrollRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, proto.MaxEnrollBody)).Decode(&req); err != nil {
		agentError(w, http.StatusBadRequest, "bad request")
		return
	}
	if req.Protocol != proto.Version {
		agentError(w, http.StatusBadRequest, "unsupported protocol version")
		return
	}
	d, err := s.store.EnrollDevice(r.Context(), req.Token, pub, req.Hostname, req.OS, req.AgentVersion, ip)
	switch {
	case errors.Is(err, store.ErrTokenInvalid):
		s.guard.fail(r.Context(), ip, "", "enrollment token")
		s.log.Warn("agent enrollment refused", "ip", ip, "hostname", req.Hostname)
		agentError(w, http.StatusForbidden, "the enrollment token is invalid, expired or used up")
		return
	case errors.Is(err, store.ErrConflict):
		agentError(w, http.StatusConflict, "this agent key is already enrolled")
		return
	case err != nil:
		s.log.Error("enrollment failed", "err", err)
		agentError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.auditAs(r, "agent", "device.enroll", "device:"+strconv.FormatInt(d.ID, 10), "%q enrolled into site %q of %q (agent %s, %s)", d.Hostname, d.Site, d.Customer, req.AgentVersion, req.OS)
	s.log.Info("device enrolled", "device", d.ID, "hostname", d.Hostname, "site", d.Site, "ip", ip)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(proto.EnrollResponse{AgentID: d.AgentID, DeviceID: d.ID, Customer: d.Customer, Site: d.Site, CommandKey: s.commandPub()})
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	pub := peerKey(r)
	if pub == nil {
		agentError(w, http.StatusUnauthorized, "an ed25519 client certificate is required")
		return
	}
	d, err := s.store.DeviceByKey(r.Context(), pub)
	if errors.Is(err, store.ErrNotFound) {
		agentError(w, http.StatusUnauthorized, "unknown agent; enroll it again")
		return
	}
	if err != nil {
		agentError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// No context takeover: a kept compression context costs 1.2 MB per agent;
	// the server seldom writes to an agent, so a pooled compressor is enough.
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionNoContextTakeover})
	if err != nil {
		return
	}
	ws.SetReadLimit(proto.MaxMessageSize)
	ctx, cancel := context.WithCancel(context.Background())
	c := &agentConn{deviceID: d.ID, agentID: d.AgentID, ws: ws, cancel: cancel, pending: map[string]chan proto.Result{}}
	s.hub.add(c)
	ip := clientIP(r)
	defer func() {
		cancel()
		if s.hub.remove(c) {
			_ = s.store.AgentDisconnected(context.Background(), d.ID)
		}
		_ = ws.CloseNow()
	}()
	s.log.Info("agent connected", "device", d.ID, "hostname", d.Hostname, "ip", ip)
	go keepAlive(ctx, ws)
	for {
		rctx, rcancel := context.WithTimeout(ctx, agentReadTimeout)
		typ, data, err := ws.Read(rctx)
		rcancel()
		if err != nil {
			s.log.Info("agent disconnected", "device", d.ID, "hostname", d.Hostname, "reason", err.Error())
			return
		}
		if typ != websocket.MessageText {
			continue
		}
		var env proto.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			_ = ws.Close(websocket.StatusUnsupportedData, "bad message")
			return
		}
		if err := s.agentMessage(ctx, c, d, ip, env); err != nil {
			s.log.Warn("agent message failed", "device", d.ID, "type", env.Type, "err", err)
		}
	}
}

func (s *Server) agentMessage(ctx context.Context, c *agentConn, d *store.Device, ip string, env proto.Envelope) error {
	switch env.Type {
	case proto.TypeHello:
		var h proto.Hello
		if err := json.Unmarshal(env.Data, &h); err != nil {
			return err
		}
		if err := s.store.AgentSeen(ctx, d.ID, &h, ip); err != nil {
			return err
		}
		if err := send(ctx, c.ws, proto.TypeWelcome, proto.Welcome{DeviceID: d.ID, HeartbeatSeconds: heartbeatSeconds, InventoryHours: inventoryHours, CommandKey: s.commandPub()}); err != nil {
			return err
		}
		go s.autoUpdate(d, h.AgentVersion) // #nosec G118 -- outlives the agent's message; own timeouts inside
		// Only this device's waiting work: after a server restart hundreds
		// of agents connect within seconds.
		go func() { // #nosec G118 -- background work, not tied to this message
			ids := []int64{d.ID}
			s.dispatchJobs(context.Background(), ids)
			s.dispatchTasks(context.Background(), ids)
		}()
		return nil
	case proto.TypeHeartbeat:
		var hb proto.Heartbeat
		if err := json.Unmarshal(env.Data, &hb); err != nil {
			return err
		}
		if err := s.store.AgentHeartbeat(ctx, d.ID, hb); err != nil {
			return err
		}
		if hb.Metrics != nil {
			if len(hb.Metrics.Disks) > 64 {
				hb.Metrics.Disks = hb.Metrics.Disks[:64]
			}
			if len(hb.Metrics.StoppedAuto) > 500 {
				hb.Metrics.StoppedAuto = hb.Metrics.StoppedAuto[:500]
			}
			return s.store.SaveMetrics(ctx, d.ID, hb.Metrics)
		}
		return nil
	case proto.TypeResult:
		var res proto.Result
		if err := json.Unmarshal(env.Data, &res); err != nil {
			return err
		}
		c.deliver(res)
		return nil
	case proto.TypePatchReport:
		var rep proto.PatchReport
		if err := json.Unmarshal(env.Data, &rep); err != nil {
			return err
		}
		return s.savePatchReport(ctx, d, &rep)
	case proto.TypeInventory:
		var inv proto.Inventory
		if err := json.Unmarshal(env.Data, &inv); err != nil {
			return err
		}
		if len(inv.Software) > 5000 {
			inv.Software = inv.Software[:5000]
		}
		if err := s.store.AgentSeen(ctx, d.ID, nil, ip); err != nil {
			return err
		}
		return s.store.SaveInventory(ctx, d.ID, &inv)
	}
	return errors.New("unknown message type " + strconv.Quote(env.Type))
}

func (s *Server) commandPub() []byte {
	if s.CommandKey == nil {
		return nil
	}
	return s.CommandKey.Public().(ed25519.PublicKey)
}
