package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/store"
)

// Windows event logs of a device (technician role, audited).

type eventsData struct {
	D       *store.Device
	Q       proto.EventQuery
	Logs    []string
	Result  *proto.EventResult
	Err     string
	Offline bool
	Asked   bool
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	q := proto.EventQuery{Log: r.FormValue("log"), Text: strings.TrimSpace(r.FormValue("text")), Max: 200}
	q.Level, _ = strconv.Atoi(r.FormValue("level"))
	q.Hours, _ = strconv.Atoi(r.FormValue("hours"))
	q.ID, _ = strconv.Atoi(r.FormValue("id"))
	if q.Log == "" {
		q.Log, q.Level, q.Hours = "System", 2, 24
	}
	if q.Hours < 1 || q.Hours > 720 {
		q.Hours = 24
	}
	if len(q.Text) > 200 {
		q.Text = q.Text[:200]
	}
	ed := &eventsData{D: d, Q: q, Logs: proto.EventLogs, Asked: r.FormValue("log") != ""}
	if ed.Asked {
		var res proto.EventResult
		err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindEventQuery, q, &res, 3*time.Minute)
		if err != nil {
			ed.Offline = errors.Is(err, ErrOffline)
			ed.Err = translate(s.lang(r, userFrom(r)), err.Error())
		} else {
			ed.Result = &res
			s.audit(r, "event.query", deviceTarget(d), "read the %s log of %q (level %d, %d hours, text %q, ID %d): %d events", q.Log, d.Hostname, q.Level, q.Hours, q.Text, q.ID, len(res.Events))
		}
	}
	s.render(w, r, http.StatusOK, "events", &Page{Title: d.Hostname, Nav: "devices", Data: ed})
}
