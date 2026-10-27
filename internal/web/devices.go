package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

// deviceFor loads a device whose customer the user may see.
func (s *Server) deviceFor(w http.ResponseWriter, r *http.Request) *store.Device {
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return nil
	}
	d, err := s.store.Device(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) || err == nil && !userFrom(r).SeesCustomer(d.CustomerID) {
		s.notFound(w, r)
		return nil
	}
	if err != nil {
		s.serverError(w, r, err)
		return nil
	}
	return d
}

type deviceData struct {
	Alerts    []store.Alert
	Metrics   *proto.Metrics
	MetricsAt *time.Time
	Stopped   []string
	D         *store.Device
	Inv       *proto.Inventory
	Online    bool
	Now       time.Time
	Software  []proto.Software
	SwQuery   string
	Package   *Packages
	Health    *store.DiskHealthState
	NetChecks []store.NetCheckState
	Fields    []store.CustomField
}

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	dd := &deviceData{D: d, Inv: d.Inventory, Online: d.Online(s.now(), onlineWindow) && s.Connected(d.ID), Now: s.now(), Package: s.packages()}
	dd.Alerts, _ = s.store.Alerts(r.Context(), userFrom(r), store.AlertFilter{DeviceID: d.ID, Open: true})
	dd.Metrics, dd.MetricsAt, dd.Stopped, _ = s.store.DeviceMetrics(r.Context(), d.ID)
	if h, err := s.store.DiskHealth(r.Context(), d.ID); err == nil {
		if x, ok := h[d.ID]; ok {
			dd.Health = &x
		}
	}
	dd.NetChecks, _ = s.store.NetChecks(r.Context(), d.ID)
	dd.Fields, _ = s.store.FieldValues(r.Context(), "device", d.ID)
	if d.Inventory != nil {
		q := strings.ToLower(strings.TrimSpace(r.FormValue("sw")))
		dd.SwQuery = q
		for _, x := range d.Inventory.Software {
			if q == "" || strings.Contains(strings.ToLower(x.Name+" "+x.Publisher), q) {
				dd.Software = append(dd.Software, x)
			}
		}
		sort.SliceStable(dd.Software, func(i, j int) bool {
			return strings.ToLower(dd.Software[i].Name) < strings.ToLower(dd.Software[j].Name)
		})
	}
	s.render(w, r, http.StatusOK, "device", &Page{Title: d.Hostname, Nav: "devices", Data: dd})
}

func (s *Server) handleDeviceRefresh(w http.ResponseWriter, r *http.Request) {
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	if !userFrom(r).CanWrite() {
		s.forbidden(w, r)
		return
	}
	to := "/devices/" + strconv.FormatInt(d.ID, 10)
	if !s.requestInventory(r.Context(), d.ID) {
		s.redirect(w, r, to, "The device is offline.")
		return
	}
	go s.collectDiskHealth(context.WithoutCancel(r.Context()), d.ID) // #nosec G118 -- after the response; own timeout
	s.audit(r, "device.inventory", "device:"+strconv.FormatInt(d.ID, 10), "inventory requested from %q", d.Hostname)
	s.redirect(w, r, to, "Inventory requested. Reload the page in a minute.")
}

func (s *Server) handleDeviceDelete(w http.ResponseWriter, r *http.Request) {
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	if !userFrom(r).CanWrite() {
		s.forbidden(w, r)
		return
	}
	// An online agent uninstalls itself first (and gives Windows Update its
	// own settings back); an offline one is removed by hand.
	removing := s.call(r.Context(), d.ID, s.issuer(r), proto.KindAgentRemove, nil, nil, 15*time.Second) == nil
	if err := s.store.DeleteDevice(r.Context(), d.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.disconnect(d.ID)
	what := "its agent can no longer connect"
	msg := "Device removed. It was offline or did not answer: uninstall the agent on the machine."
	if removing {
		what = "its agent is uninstalling itself"
		msg = "Device removed. The agent uninstalls itself from the computer in a few seconds."
	}
	s.audit(r, "device.delete", "device:"+strconv.FormatInt(d.ID, 10), "removed device %q from site %q of %q; %s", d.Hostname, d.Site, d.Customer, what)
	s.redirect(w, r, "/sites/"+strconv.FormatInt(d.SiteID, 10), msg)
}

// ---- template helpers

// Bytes formats a size (1024-based, as Windows shows it).
func (p *Page) Bytes(n uint64) string { return formatBytes(n) }

func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// Percent is used/total in percent.
func (p *Page) Percent(free, size uint64) int {
	if size == 0 {
		return 0
	}
	return int(100 - free*100/size)
}

// Ago is a short relative time.
func (p *Page) Ago(t any) string {
	var tt time.Time
	switch v := t.(type) {
	case time.Time:
		tt = v
	case *time.Time:
		if v == nil {
			return "—"
		}
		tt = *v
	}
	if tt.IsZero() {
		return "—"
	}
	d := time.Since(tt)
	switch {
	case d < time.Minute:
		return p.T("just now")
	case d < time.Hour:
		return p.T("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return p.T("%d h ago", int(d.Hours()))
	}
	return p.T("%d days ago", int(d.Hours()/24))
}

// Uptime is the time since boot.
func (p *Page) Uptime(boot any) string {
	var b time.Time
	switch v := boot.(type) {
	case time.Time:
		b = v
	case *time.Time:
		if v == nil {
			return "—"
		}
		b = *v
	}
	if b.IsZero() {
		return "—"
	}
	d := time.Since(b)
	days := int(d.Hours()) / 24
	if days > 0 {
		return p.T("%d d %d h", days, int(d.Hours())%24)
	}
	return p.T("%d h %d min", int(d.Hours()), int(d.Minutes())%60)
}

// Zone names the server's time zone, e.g. "CEST, UTC+02:00"; times in the
// console are shown in it.
func (p *Page) Zone() string { return time.Now().Format("MST, UTC-07:00") }

// ClockInfo feeds the sidebar clock.
type ClockInfo struct {
	Text string
	MS   int64
	Off  int
}

// Clock is the server's time; app.js keeps it ticking from this value, so
// a wrong clock of the viewer's PC does not matter.
func (p *Page) Clock() ClockInfo {
	now := time.Now()
	_, off := now.Zone()
	return ClockInfo{Text: now.Format("2006-01-02 15:04:05"), MS: now.UnixMilli(), Off: off}
}

// powerPop is the argument of the powerpop template (restart or shutdown).
type powerPop struct {
	P      *Page
	Action string
}
