package web

import (
	"context"
	"net/http"
)

const settingRemote = "remote_desktop"

// RemoteSettings control remote desktop sessions.
type RemoteSettings struct {
	// ShowNotice shows a notice on the remote screen while a technician is
	// connected (default on).
	ShowNotice bool `json:"show_notice"`
}

func defaultRemote() RemoteSettings { return RemoteSettings{ShowNotice: true} }

// Remote loads the remote desktop settings.
func (s *Server) Remote(ctx context.Context) RemoteSettings {
	x := defaultRemote()
	if err := s.store.GetSetting(ctx, settingRemote, &x); err != nil {
		return defaultRemote()
	}
	return x
}

func (s *Server) handleRemoteSettings(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "rdsettings", &Page{Title: "Remote desktop", Nav: "settings", Data: s.Remote(r.Context())})
}

func (s *Server) handleRemoteSave(w http.ResponseWriter, r *http.Request) {
	x := RemoteSettings{ShowNotice: r.FormValue("show_notice") == "1"}
	if err := s.store.SetSetting(r.Context(), settingRemote, x); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.remote", "settings", "remote desktop notice on the remote screen: %v", x.ShowNotice)
	s.redirect(w, r, "/settings/remote", "Saved.")
}
