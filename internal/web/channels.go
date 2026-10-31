package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/rmmzit/internal/auth"
	"github.com/max-zit/rmmzit/internal/store"
)

// Chat and webhook channels: alerts also go to Slack, Microsoft Teams or
// any HTTP endpoint (JSON, optionally signed with HMAC-SHA256). The URLs
// and secrets are stored encrypted.

const settingChannels = "channels"

// Channel kinds.
const (
	ChannelSlack   = "slack"
	ChannelTeams   = "teams"
	ChannelWebhook = "webhook"
)

// Channel is one destination of alert notifications.
type Channel struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	URL       string `json:"url"`              // sealed
	Secret    string `json:"secret,omitempty"` // sealed, webhook only
	Critical  bool   `json:"critical"`         // only critical alerts
	OnResolve bool   `json:"on_resolve"`
}

func (s *Server) channels(ctx context.Context) []Channel {
	var list []Channel
	if err := s.store.GetSetting(ctx, settingChannels, &list); err != nil {
		return nil
	}
	return list
}

func (s *Server) saveChannels(ctx context.Context, list []Channel) error {
	return s.store.SetSetting(ctx, settingChannels, list)
}

func (s *Server) channelURL(c Channel) (string, error) {
	return s.store.OpenSecret("settings.channel.url."+c.ID, c.URL)
}

// alertEvent is the JSON of a webhook notification.
type alertEvent struct {
	Event    string    `json:"event"` // alert.opened, alert.resolved, test
	Severity string    `json:"severity"`
	Kind     string    `json:"kind"`
	Title    string    `json:"title"`
	Key      string    `json:"key,omitempty"`
	Message  string    `json:"message"`
	Device   string    `json:"device"`
	DeviceID int64     `json:"device_id"`
	Customer string    `json:"customer"`
	Site     string    `json:"site"`
	Opened   time.Time `json:"opened_at"`
	Resolved time.Time `json:"resolved_at,omitzero"`
}

func (e alertEvent) line() string {
	icon := map[string]string{"critical": "🔴", "warning": "🟠"}[e.Severity]
	if e.Event == "alert.resolved" {
		icon = "✅"
	}
	title := e.Title
	if e.Key != "" {
		title += " (" + e.Key + ")"
	}
	state := strings.ToUpper(e.Severity)
	if e.Event == "alert.resolved" {
		state = "RESOLVED"
	}
	return fmt.Sprintf("%s %s: %s on %s (%s / %s): %s", icon, state, title, e.Device, e.Customer, e.Site, e.Message)
}

// payload builds the request body for a channel.
func payload(kind string, events []alertEvent) ([]byte, error) {
	switch kind {
	case ChannelSlack:
		var b strings.Builder
		for _, e := range events {
			b.WriteString(e.line() + "\n")
		}
		return json.Marshal(map[string]string{"text": strings.TrimSpace(b.String())})
	case ChannelTeams:
		// A Teams workflow "when a webhook request is received" posts this card.
		var body []map[string]any
		for _, e := range events {
			body = append(body, map[string]any{"type": "TextBlock", "text": e.line(), "wrap": true})
		}
		return json.Marshal(map[string]any{"type": "message", "attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content":     map[string]any{"type": "AdaptiveCard", "version": "1.4", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "body": body},
		}}})
	default:
		return json.Marshal(map[string]any{"source": "RMMZit", "events": events})
	}
}

var channelClient = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// postChannel sends events to one channel.
func (s *Server) postChannel(ctx context.Context, c Channel, events []alertEvent) error {
	u, err := s.channelURL(c)
	if err != nil {
		return errors.New("the channel URL cannot be read; enter it again")
	}
	body, err := payload(c.Kind, events)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "RMMZit/"+s.Version)
	if c.Kind == ChannelWebhook && c.Secret != "" {
		secret, err := s.store.OpenSecret("settings.channel.secret."+c.ID, c.Secret)
		if err == nil {
			m := hmac.New(sha256.New, []byte(secret))
			m.Write(body)
			req.Header.Set("X-RMMZit-Signature", "sha256="+hex.EncodeToString(m.Sum(nil)))
		}
	}
	resp, err := channelClient.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the channel: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("the channel answered %s", resp.Status)
	}
	return nil
}

// notifyChannels sends opened (and, per channel, resolved) alerts.
func (s *Server) notifyChannels(ctx context.Context, opened, resolved []store.Alert, devs map[int64]store.MonitorState) {
	list := s.channels(ctx)
	if len(list) == 0 || len(opened)+len(resolved) == 0 {
		return
	}
	ev := func(a store.Alert, event string) alertEvent {
		d := devs[a.DeviceID]
		e := alertEvent{Event: event, Severity: a.Severity, Kind: a.Kind, Title: alertTitles[a.Kind], Key: a.Key, Message: a.Message,
			Device: d.Hostname, DeviceID: a.DeviceID, Customer: d.Customer, Site: d.Site, Opened: a.OpenedAt}
		if a.ResolvedAt != nil {
			e.Resolved = *a.ResolvedAt
		}
		return e
	}
	for _, c := range list {
		var events []alertEvent
		for _, a := range opened {
			if !c.Critical || a.Severity == "critical" {
				events = append(events, ev(a, "alert.opened"))
			}
		}
		if c.OnResolve {
			for _, a := range resolved {
				if !c.Critical || a.Severity == "critical" {
					events = append(events, ev(a, "alert.resolved"))
				}
			}
		}
		if len(events) == 0 {
			continue
		}
		if len(events) > 50 {
			events = events[:50]
		}
		go func(c Channel, events []alertEvent) { // #nosec G118 -- posting must not end with the monitor pass; own 30 s timeout
			cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := s.postChannel(cctx, c, events); err != nil {
				s.log.Warn("alert channel failed", "channel", c.Name, "err", err)
				_ = s.store.Audit(cctx, "-", "server", "alert.channel.failed", "settings", "channel "+c.Name+": "+err.Error())
			}
		}(c, events)
	}
}

// ---- console (Settings → Monitoring and alerts)

func checkChannelURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return errors.New("enter the full https:// address of the channel")
	}
	return nil
}

func (s *Server) handleChannels(w http.ResponseWriter, r *http.Request) {
	back := "/settings/monitoring#channels"
	list := s.channels(r.Context())
	idx := -1
	for i, c := range list {
		if c.ID == r.FormValue("id") {
			idx = i
		}
	}
	lang := s.lang(r, userFrom(r))
	switch r.FormValue("action") {
	case "add":
		c := Channel{ID: auth.RandomToken(8), Name: strings.TrimSpace(r.FormValue("name")), Kind: r.FormValue("kind"),
			Critical: r.FormValue("critical") == "1", OnResolve: r.FormValue("on_resolve") == "1"}
		raw := strings.TrimSpace(r.FormValue("url"))
		if c.Name == "" || len(c.Name) > 80 || (c.Kind != ChannelSlack && c.Kind != ChannelTeams && c.Kind != ChannelWebhook) {
			s.redirect(w, r, back, "Enter a name and choose the type.")
			return
		}
		if err := checkChannelURL(raw); err != nil {
			s.redirect(w, r, back, err.Error())
			return
		}
		if len(list) >= 20 {
			s.redirect(w, r, back, "At most 20 channels.")
			return
		}
		c.URL = s.store.SealSecret("settings.channel.url."+c.ID, raw)
		if sec := r.FormValue("secret"); sec != "" && c.Kind == ChannelWebhook {
			c.Secret = s.store.SealSecret("settings.channel.secret."+c.ID, sec)
		}
		list = append(list, c)
		if err := s.saveChannels(r.Context(), list); err != nil {
			s.serverError(w, r, err)
			return
		}
		host := ""
		if u, err := url.Parse(raw); err == nil {
			host = u.Host
		}
		s.audit(r, "channel.add", "settings", "alert channel %q added (%s, %s, critical only: %v, resolved: %v)", c.Name, c.Kind, host, c.Critical, c.OnResolve)
		s.redirect(w, r, back, "Saved.")
	case "delete":
		if idx < 0 {
			s.redirect(w, r, back, "Unknown action.")
			return
		}
		name := list[idx].Name
		list = append(list[:idx], list[idx+1:]...)
		if err := s.saveChannels(r.Context(), list); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.audit(r, "channel.delete", "settings", "alert channel %q removed", name)
		s.redirect(w, r, back, translate(lang, "Channel %s removed.", name))
	case "test":
		if idx < 0 {
			s.redirect(w, r, back, "Unknown action.")
			return
		}
		c := list[idx]
		ev := alertEvent{Event: "test", Severity: "warning", Kind: "test", Title: "Test notification", Message: "RMMZit can post to this channel.",
			Device: "TEST-PC", Customer: "RMMZit", Site: "-", Opened: s.now()}
		err := s.postChannel(r.Context(), c, []alertEvent{ev})
		s.audit(r, "channel.test", "settings", "test notification to %q: %v", c.Name, errOrOK(err))
		if err != nil {
			s.redirect(w, r, back, err.Error())
			return
		}
		s.redirect(w, r, back, translate(lang, "Test sent to %s.", c.Name))
	default:
		s.redirect(w, r, back, "Unknown action.")
	}
}

func errOrOK(err error) string {
	if err != nil {
		return err.Error()
	}
	return "ok"
}

// ChannelRows are the channels for the settings page (no URLs).
func (s *Server) channelRows(ctx context.Context) []map[string]string {
	var out []map[string]string
	for _, c := range s.channels(ctx) {
		out = append(out, map[string]string{"ID": c.ID, "Name": c.Name, "Kind": c.Kind,
			"Critical": strconv.FormatBool(c.Critical), "OnResolve": strconv.FormatBool(c.OnResolve), "Signed": strconv.FormatBool(c.Secret != "")})
	}
	return out
}
