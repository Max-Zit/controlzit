package web

import (
	"context"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/max-zit/controlzit/internal/auth"
	"github.com/max-zit/controlzit/internal/proto"
)

// Terminal (Linux devices): a root shell in the browser. Sessions use the
// remote desktop hub and stream endpoint; the server copies messages
// between the browser and the agent without looking into them, and audits
// the start and the end (not the keystrokes, which may hold passwords).

func (s *Server) handleTerm(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	data := &rdData{D: d, Online: s.Connected(d.ID), Window: r.FormValue("w") == "1"}
	page := "term"
	if data.Window {
		page = "termwin"
	}
	s.render(w, r, http.StatusOK, page, &Page{Title: d.Hostname, Nav: "devices", Data: data})
}

func (s *Server) handleTermSocket(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	u := userFrom(r)
	cols, _ := strconv.Atoi(r.FormValue("cols"))
	rows, _ := strconv.Atoi(r.FormValue("rows"))
	if !proto.ValidTermSize(cols, rows) {
		cols, rows = 120, 32
	}
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
	if d.IsWindows() {
		fail("The terminal is available on Linux devices. On Windows, use Scripts.")
		return
	}
	name := u.DisplayName
	if name == "" {
		name = u.Username
	}
	if err := s.call(ctx, d.ID, u.Username, proto.KindTermStart, proto.TermStart{Session: sess.id, Token: sess.token, Technician: name, Cols: cols, Rows: rows}, nil, rdStartTimeout); err != nil {
		s.log.Warn("terminal start failed", "device", d.ID, "err", err)
		fail(err.Error())
		return
	}
	var aws *websocket.Conn
	select {
	case aws = <-sess.stream:
	case <-time.After(rdStartTimeout):
		fail("the terminal did not connect")
		return
	}
	defer aws.CloseNow()
	start := s.now()
	s.audit(r, "term.start", "device:"+strconv.FormatInt(d.ID, 10), "terminal session %s to %q started (root shell)", sess.id, d.Hostname)

	var bytesDown, bytesUp atomic.Int64
	errc := make(chan error, 2)
	go func() { // agent → browser
		for {
			typ, data, err := aws.Read(ctx)
			if err != nil {
				errc <- err
				return
			}
			bytesDown.Add(int64(len(data)))
			wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
			err = bws.Write(wctx, typ, data)
			wcancel()
			if err != nil {
				errc <- err
				return
			}
		}
	}()
	go func() { // browser → agent: text only
		for {
			typ, data, err := bws.Read(ctx)
			if err != nil {
				errc <- err
				return
			}
			if typ != websocket.MessageText {
				continue
			}
			bytesUp.Add(int64(len(data)))
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
	r = r.WithContext(context.Background())
	dur := s.now().Sub(start).Round(time.Second)
	s.audit(r, "term.end", "device:"+strconv.FormatInt(d.ID, 10), "terminal session %s to %q ended after %s (%d KB shown, %d KB typed)", sess.id, d.Hostname, dur, bytesDown.Load()>>10, bytesUp.Load()>>10)
	s.log.Info("terminal session ended", "device", d.ID, "session", sess.id, "duration", dur.String(), "reason", errString(err))
}
