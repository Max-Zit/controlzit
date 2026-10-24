package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/max-zit/controlzit/internal/proto"
)

// pinnedTLS trusts exactly the server certificate with the fingerprint
// (no certificate authorities) and presents the agent's key.
func pinnedTLS(fingerprint string, cert tls.Certificate) *tls.Config {
	want, _ := hex.DecodeString(fingerprint)
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		// The chain is checked by VerifyConnection against the pin.
		InsecureSkipVerify: true, // #nosec G402 -- certificate pinning below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server sent no certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return fmt.Errorf("%w (got %s)", ErrPinMismatch, hex.EncodeToString(got[:]))
			}
			return nil
		},
	}
}

func httpClient(tc *tls.Config) *http.Client {
	tr := &http.Transport{TLSClientConfig: tc, ForceAttemptHTTP2: false, TLSHandshakeTimeout: 15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second, IdleConnTimeout: 90 * time.Second, Proxy: http.ProxyFromEnvironment}
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}
}

// Enroll registers this machine with the server using an enrollment token.
func Enroll(ctx context.Context, dir, serverURL, fingerprint, token string) (*Config, error) {
	serverURL, err := CheckServerURL(serverURL)
	if err != nil {
		return nil, err
	}
	fingerprint, err = CheckFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("an enrollment token is required")
	}
	if err := EnsureDir(dir); err != nil {
		return nil, err
	}
	priv, err := LoadOrCreateKey(dir)
	if err != nil {
		return nil, err
	}
	cert, err := clientCert(priv)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	si := basicInfo()
	body, _ := json.Marshal(proto.EnrollRequest{Protocol: proto.Version, Token: token, Hostname: host, OS: si.OS, AgentVersion: Version})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+proto.PathEnroll, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "controlzit-agent/"+Version)
	resp, err := httpClient(pinnedTLS(fingerprint, cert)).Do(req)
	if errors.Is(err, ErrPinMismatch) {
		return nil, &RefusedError{Msg: err.Error()}
	}
	if err != nil {
		return nil, fmt.Errorf("cannot reach the server: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		var e proto.Error
		msg := fmt.Sprintf("HTTP %d", resp.StatusCode)
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			return nil, fmt.Errorf("server error: %s", msg)
		}
		return nil, &RefusedError{Msg: msg}
	}
	var er proto.EnrollResponse
	if err := json.Unmarshal(raw, &er); err != nil || er.AgentID == "" {
		return nil, errors.New("unexpected answer from the server")
	}
	c := &Config{ServerURL: serverURL, Fingerprint: fingerprint, AgentID: er.AgentID, DeviceID: er.DeviceID,
		Customer: er.Customer, Site: er.Site, EnrolledAt: time.Now().UTC(), CommandKey: er.CommandKey}
	if err := c.Save(dir); err != nil {
		return nil, err
	}
	_ = os.Remove(filepath.Join(dir, pendingFile))
	markEnrolled(true)
	return c, nil
}

// ErrPinMismatch: the server is not the one the agent was told to trust.
var ErrPinMismatch = errors.New("server certificate does not match the pinned fingerprint")

// RefusedError is a definitive refusal (wrong token, wrong server); trying
// again with the same data does not help.
type RefusedError struct{ Msg string }

func (e *RefusedError) Error() string { return "enrollment refused: " + e.Msg }

// Agent runs the channel to the server.
type Agent struct {
	Dir string
	Cfg *Config
	Log *slog.Logger
	// Collect gathers the inventory (replaced in tests).
	Collect func(ctx context.Context) *proto.Inventory
	// Info returns the quick status for hello and heartbeat (tests).
	Info func() SysInfo
	// Metrics samples the machine for heartbeats (tests).
	Metrics func(ctx context.Context) *proto.Metrics

	key ed25519.PrivateKey
	// lastInventory survives reconnects, so a server restart does not make
	// every agent send its inventory again.
	lastInventory time.Time
	// status is published for the tray icon.
	status Status
	// patch is the Windows Update state; runCtx outlives a connection.
	patch  *patchState
	runCtx context.Context
}

// SysInfo is the cheap status sent with hello and heartbeats.
type SysInfo struct {
	OS, OSVersion, OSBuild string
	BootTime               time.Time
	LoggedOnUser           string
}

// Run connects and reconnects until ctx ends.
func (a *Agent) Run(ctx context.Context) error {
	key, err := LoadOrCreateKey(a.Dir)
	if err != nil {
		return err
	}
	a.key = key
	helperDir = a.Dir
	self = a
	a.runCtx = ctx
	a.initPatches()
	if err := ApplyWUPolicy(a.Dir); err != nil {
		a.Log.Warn("cannot switch off the automatic Windows Update installation", "err", err)
	}
	if a.Collect == nil {
		a.Collect = CollectInventory
	}
	if a.Info == nil {
		a.Info = basicInfo
	}
	if a.Metrics == nil {
		a.Metrics = CollectMetrics
	}
	backoff := 2 * time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := a.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, errUnknownAgent) {
			a.Log.Error("the server does not know this agent (device removed?); enroll it again", "err", err)
			backoff = 10 * time.Minute
		} else {
			a.Log.Warn("connection to the server lost", "err", err)
			if time.Since(start) > 5*time.Minute {
				backoff = 2 * time.Second
			}
		}
		// Jitter, so many agents do not reconnect at the same moment.
		wait := backoff + time.Duration(rand.Int64N(int64(backoff/2)+1)) // #nosec G404 -- jitter only
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		// At most about a minute and a half: after a server restart the
		// devices should be back online quickly.
		if backoff < time.Minute {
			backoff = min(backoff*2, time.Minute)
		}
	}
	return nil
}

var errUnknownAgent = errors.New("unknown agent")

func sendMsg(ctx context.Context, ws *websocket.Conn, typ string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(proto.Envelope{Type: typ, Data: raw})
	wctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return ws.Write(wctx, websocket.MessageText, b)
}

// session is one connection: hello, then heartbeats and inventory.
func (a *Agent) session(ctx context.Context) error {
	cert, err := clientCert(a.key)
	if err != nil {
		return err
	}
	hc := httpClient(pinnedTLS(a.Cfg.Fingerprint, cert))
	hc.Timeout = 0 // the channel is long-lived
	dctx, dcancel := context.WithTimeout(ctx, 30*time.Second)
	ws, resp, err := websocket.Dial(dctx, a.Cfg.ServerURL+proto.PathConnect, &websocket.DialOptions{
		HTTPClient: hc, HTTPHeader: http.Header{"User-Agent": {"controlzit-agent/" + Version}},
		CompressionMode: websocket.CompressionContextTakeover,
	})
	dcancel()
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return errUnknownAgent
		}
		return err
	}
	defer ws.CloseNow()
	ws.SetReadLimit(proto.MaxMessageSize)
	si := a.Info()
	host, _ := os.Hostname()
	if err := sendMsg(ctx, ws, proto.TypeHello, proto.Hello{Protocol: proto.Version, AgentVersion: Version, Hostname: host,
		OS: si.OS, OSVersion: si.OSVersion, OSBuild: si.OSBuild, BootTime: si.BootTime, LoggedOnUser: si.LoggedOnUser}); err != nil {
		return err
	}
	a.Log.Info("connected to the server", "server", a.Cfg.ServerURL)
	a.publishStatus(true)
	defer a.publishStatus(false)

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	msgs := make(chan proto.Envelope, 8)
	readErr := make(chan error, 1)
	go func() {
		for {
			typ, data, err := ws.Read(sctx)
			if err != nil {
				readErr <- err
				return
			}
			if typ != websocket.MessageText {
				continue
			}
			var env proto.Envelope
			if json.Unmarshal(data, &env) == nil {
				select {
				case msgs <- env:
				case <-sctx.Done():
					return
				}
			}
		}
	}()

	heartbeat := time.NewTicker(60 * time.Second)
	defer heartbeat.Stop()
	// The first heartbeat with metrics soon after connecting.
	firstBeat := time.After(10 * time.Second)
	inventoryEvery := 12 * time.Hour
	nextInventory := a.lastInventory.Add(inventoryEvery) // zero: right after connecting
	invTimer := time.NewTimer(5 * time.Second)
	defer invTimer.Stop()
	// Windows Update: resend the last report, scan when due.
	a.markPatchesUnsent()
	select {
	case a.patch.notify <- struct{}{}:
	default:
	}
	patchTimer := time.NewTimer(2 * time.Minute)
	defer patchTimer.Stop()
	invDone := make(chan *proto.Inventory, 1)
	collecting := false
	collect := func() {
		if collecting {
			return
		}
		collecting = true
		go func() {
			cctx, ccancel := context.WithTimeout(sctx, 5*time.Minute)
			defer ccancel()
			invDone <- a.Collect(cctx)
		}()
	}
	for {
		select {
		case <-ctx.Done():
			_ = ws.Close(websocket.StatusNormalClosure, "agent stopping")
			return ctx.Err()
		case err := <-readErr:
			return err
		case env := <-msgs:
			switch env.Type {
			case proto.TypeWelcome:
				var w proto.Welcome
				if json.Unmarshal(env.Data, &w) == nil {
					if w.HeartbeatSeconds >= 10 && w.HeartbeatSeconds <= 3600 {
						heartbeat.Reset(time.Duration(w.HeartbeatSeconds) * time.Second)
					}
					if w.InventoryHours >= 1 && w.InventoryHours <= 24*7 {
						inventoryEvery = time.Duration(w.InventoryHours) * time.Hour
					}
					a.learnCommandKey(w.CommandKey)
				}
			case proto.TypeInventoryRequest:
				collect()
			case proto.TypeCommand:
				var sc proto.SignedCommand
				if json.Unmarshal(env.Data, &sc) == nil {
					go a.runCommand(sctx, ws, sc)
				}
			}
		case <-heartbeat.C:
			if err := a.heartbeat(sctx, ws); err != nil {
				return err
			}
		case <-firstBeat:
			firstBeat = nil
			if err := a.heartbeat(sctx, ws); err != nil {
				return err
			}
		case <-invTimer.C:
			if time.Now().After(nextInventory) || time.Now().Equal(nextInventory) {
				collect()
			}
			invTimer.Reset(time.Minute)
		case <-a.patch.notify:
			if r := a.pendingPatchReport(); r != nil {
				if err := sendMsg(ctx, ws, proto.TypePatchReport, r); err != nil {
					a.markPatchesUnsent()
					return err
				}
			}
		case <-patchTimer.C:
			if a.scanDue() {
				_ = a.startPatchJob(a.scanJob)
			}
			patchTimer.Reset(30 * time.Minute)
		case inv := <-invDone:
			collecting = false
			a.lastInventory = time.Now()
			nextInventory = a.lastInventory.Add(inventoryEvery)
			if err := sendMsg(ctx, ws, proto.TypeInventory, inv); err != nil {
				return err
			}
			a.Log.Info("inventory sent", "software", len(inv.Software), "errors", len(inv.Errors))
		}
	}
}

// BasicOS is a fallback OS description.
func BasicOS() string { return runtime.GOOS + "/" + runtime.GOARCH }

func (a *Agent) heartbeat(ctx context.Context, ws *websocket.Conn) error {
	si := a.Info()
	m := a.Metrics(ctx)
	a.publishStatus(true)
	return sendMsg(ctx, ws, proto.TypeHeartbeat, proto.Heartbeat{BootTime: si.BootTime, LoggedOnUser: si.LoggedOnUser, Metrics: m})
}
