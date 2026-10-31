package web

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/max-zit/rmmzit/internal/auth"
	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/store"
)

// Remote desktop relay. The technician's browser opens a WebSocket on the
// console; the server sends the signed rd.start command, the agent's helper
// connects a stream to the agent endpoint with the one-time token, and the
// server copies messages between the two. It does not look into the screen
// data.

const (
	rdStartTimeout = 30 * time.Second
	// maxBrowserMsg limits a message from the browser (input, paste).
	maxBrowserMsg = 256 << 10
)

type rdSession struct {
	id, token  string
	deviceID   int64
	technician string
	stream     chan *websocket.Conn
	done       chan struct{}
}

type rdHub struct {
	mu       sync.Mutex
	sessions map[string]*rdSession
}

func (h *rdHub) add(s *rdSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sessions == nil {
		h.sessions = map[string]*rdSession{}
	}
	h.sessions[s.id] = s
}

func (h *rdHub) take(id string) *rdSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[id]
}

func (h *rdHub) remove(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.sessions, id)
}

type rdData struct {
	D         *store.Device
	Online    bool
	Notice    bool
	Clipboard bool
	Window    bool // in its own browser window
}

// handleRD is the viewer page.
func (s *Server) handleRD(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	data := &rdData{D: d, Online: s.Connected(d.ID), Notice: s.Remote(r.Context()).ShowNotice, Clipboard: s.Remote(r.Context()).Clipboard && d.IsWindows(), Window: r.FormValue("w") == "1"}
	page := "rd"
	if data.Window {
		page = "rdwin"
	}
	s.render(w, r, http.StatusOK, page, &Page{Title: d.Hostname, Nav: "devices", Data: data})
}

// handleRDSocket is the browser side of a session.
func (s *Server) handleRDSocket(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	u := userFrom(r)
	// Accept checks that the Origin is this console (no cross-site sockets).
	bws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer bws.CloseNow()
	bws.SetReadLimit(maxBrowserMsg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess := &rdSession{id: auth.RandomToken(12), token: auth.RandomToken(32), deviceID: d.ID, technician: u.Username,
		stream: make(chan *websocket.Conn, 1), done: make(chan struct{})}
	s.rd.add(sess)
	defer func() {
		s.rd.remove(sess.id)
		close(sess.done)
	}()
	fail := func(msg string) {
		_ = bws.Write(ctx, websocket.MessageText, []byte(`{"t":"error","text":`+strconv.Quote(translate(s.lang(r, u), msg))+`}`))
		_ = bws.Close(websocket.StatusNormalClosure, "")
	}
	name := u.DisplayName
	if name == "" {
		name = u.Username
	}
	lang := s.lang(r, u)
	settings := s.Remote(ctx)
	if !d.IsWindows() {
		settings.Clipboard = false // not on Linux yet
	}
	if err := s.call(ctx, d.ID, u.Username, proto.KindRDStart, proto.RDStart{Session: sess.id, Token: sess.token, Technician: name, NoNotice: !settings.ShowNotice, NoClipboard: !settings.Clipboard}, nil, rdStartTimeout); err != nil {
		s.log.Warn("remote desktop start failed", "device", d.ID, "err", err)
		fail(err.Error())
		return
	}
	var aws *websocket.Conn
	select {
	case aws = <-sess.stream:
	case <-time.After(rdStartTimeout):
		fail("the remote desktop helper did not connect")
		return
	}
	defer aws.CloseNow()
	start := s.now()
	s.audit(r, "rd.start", "device:"+strconv.FormatInt(d.ID, 10), "remote desktop session %s to %q started (notice on screen: %v, clipboard: %v)", sess.id, d.Hostname, settings.ShowNotice, settings.Clipboard)
	s.log.Info("remote desktop session started", "device", d.ID, "user", u.Username, "session", sess.id)

	var bytesDown atomic.Int64
	var clipIn, clipOut atomic.Int64 // clipboard texts to and from the remote computer
	errc := make(chan error, 2)
	go func() { // agent → browser
		for {
			typ, data, err := aws.Read(ctx)
			if err != nil {
				errc <- err
				return
			}
			bytesDown.Add(int64(len(data)))
			if typ == websocket.MessageText && bytes.Contains(data, []byte(`"t":"error"`)) {
				data = translateReply(data, lang) // the helper writes English
			}
			if typ == websocket.MessageBinary && len(data) > 0 && data[0] == proto.RDClip {
				if !settings.Clipboard {
					continue
				}
				clipOut.Add(1)
			}
			wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
			err = bws.Write(wctx, typ, data)
			wcancel()
			if err != nil {
				errc <- err
				return
			}
		}
	}()
	go func() { // browser → agent: input as text only
		for {
			typ, data, err := bws.Read(ctx)
			if err != nil {
				errc <- err
				return
			}
			if typ != websocket.MessageText {
				continue
			}
			if isClip(data) {
				if !settings.Clipboard {
					continue
				}
				clipIn.Add(1)
			}
			wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
			err = aws.Write(wctx, websocket.MessageText, data)
			wcancel()
			if err != nil {
				errc <- err
				return
			}
		}
	}()
	err = <-errc
	cancel()
	// The request context ends with the browser connection; log without its
	// cancellation (the signed-in user stays in it).
	r = r.WithContext(context.WithoutCancel(r.Context()))
	dur := s.now().Sub(start).Round(time.Second)
	s.audit(r, "rd.end", "device:"+strconv.FormatInt(d.ID, 10), "remote desktop session %s to %q ended after %s (%s sent; clipboard: %d texts to the computer, %d from it)", sess.id, d.Hostname, dur, formatBytes(uint64(bytesDown.Load())), clipIn.Load(), clipOut.Load()) // #nosec G115 -- a byte count
	s.log.Info("remote desktop session ended", "device", d.ID, "session", sess.id, "duration", dur.String(), "reason", errString(err))
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// handleStream is the agent side: the helper connects with the device's
// TLS identity and the session token.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	pub := peerKey(r)
	if pub == nil {
		agentError(w, http.StatusUnauthorized, "an ed25519 client certificate is required")
		return
	}
	d, err := s.store.DeviceByKey(r.Context(), pub)
	if err != nil {
		agentError(w, http.StatusUnauthorized, "unknown agent")
		return
	}
	sess := s.rd.take(r.URL.Query().Get("session"))
	if sess == nil || sess.deviceID != d.ID || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Cz-Session-Token")), []byte(sess.token)) != 1 {
		agentError(w, http.StatusForbidden, "no such remote desktop session")
		return
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(proto.MaxMessageSize)
	select {
	case sess.stream <- ws:
	default: // a second stream for the same session
		_ = ws.Close(websocket.StatusPolicyViolation, "session already connected")
		return
	}
	<-sess.done
}

// isClip reports whether a browser message sets the remote clipboard.
func isClip(data []byte) bool {
	if !bytes.Contains(data, []byte(`"clip"`)) {
		return false
	}
	var m struct {
		T string `json:"t"`
	}
	return json.Unmarshal(data, &m) == nil && m.T == "clip"
}

// translateReply translates the text of an error message from the helper.
func translateReply(data []byte, lang string) []byte {
	var m proto.RDReply
	if json.Unmarshal(data, &m) != nil || m.Text == "" {
		return data
	}
	m.Text = translate(lang, m.Text)
	b, err := json.Marshal(m)
	if err != nil {
		return data
	}
	return b
}
