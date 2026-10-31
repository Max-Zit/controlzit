package web

import (
	"net/http"
	"sort"
	"strings"

	"github.com/max-zit/rmmzit/internal/store"
)

// The search of the header (Ctrl+K): devices by name, user, serial number,
// IP or MAC address; customers; installed programs; vulnerabilities by ID.

type searchHit struct {
	Device *store.Device
	Why    string // what matched, when it is not the name
}

type searchProgram struct {
	Name    string
	Devices []*store.Device
}

type searchVuln struct {
	ID      string
	Product string
	Devices []*store.Device
}

type searchData struct {
	Q         string
	Devices   []searchHit
	Customers []store.Customer
	Programs  []searchProgram
	Vulns     []searchVuln
}

const searchMax = 50

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := userFrom(r)
	d := &searchData{Q: strings.TrimSpace(r.FormValue("q"))}
	if len(d.Q) > 100 {
		d.Q = d.Q[:100]
	}
	q := strings.ToLower(d.Q)
	if len(q) < 2 {
		s.render(w, r, http.StatusOK, "search", &Page{Title: "Search", Data: d})
		return
	}
	devs, err := s.store.Devices(ctx, u, store.DeviceFilter{Limit: 2000})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	byID := map[int64]*store.Device{}
	for _, x := range devs {
		byID[x.ID] = x
	}
	invs, _ := s.store.Inventories(ctx)
	has := func(v string) bool { return v != "" && strings.Contains(strings.ToLower(v), q) }
	for _, x := range devs {
		hit := searchHit{Device: x}
		switch {
		case has(x.Hostname):
		case has(x.LastUser):
			hit.Why = x.LastUser
		case has(x.OS):
			hit.Why = x.OS
		default:
			inv := invs[x.ID]
			if inv == nil {
				continue
			}
			if has(inv.Hardware.Serial) {
				hit.Why = inv.Hardware.Serial
				break
			}
			for _, n := range inv.Network {
				for _, ip := range n.IPs {
					if has(ip) {
						hit.Why = ip
					}
				}
				if hit.Why == "" && has(n.MAC) {
					hit.Why = n.MAC
				}
			}
			if hit.Why == "" {
				continue
			}
		}
		if len(d.Devices) < searchMax {
			d.Devices = append(d.Devices, hit)
		}
	}
	if cs, err := s.store.Customers(ctx, u); err == nil {
		for _, c := range cs {
			if has(c.Name) && len(d.Customers) < searchMax {
				d.Customers = append(d.Customers, c)
			}
		}
	}
	progs := map[string]*searchProgram{}
	for id, inv := range invs {
		x := byID[id]
		if x == nil {
			continue
		}
		seen := map[string]bool{}
		for _, sw := range inv.Software {
			if !has(sw.Name) || seen[sw.Name] {
				continue
			}
			seen[sw.Name] = true
			p := progs[sw.Name]
			if p == nil {
				p = &searchProgram{Name: sw.Name}
				progs[sw.Name] = p
			}
			p.Devices = append(p.Devices, x)
		}
	}
	for _, p := range progs {
		d.Programs = append(d.Programs, *p)
	}
	sort.Slice(d.Programs, func(i, j int) bool { return strings.ToLower(d.Programs[i].Name) < strings.ToLower(d.Programs[j].Name) })
	if len(d.Programs) > searchMax {
		d.Programs = d.Programs[:searchMax]
	}
	if strings.HasPrefix(q, "cve-") || strings.Contains(q, "-cve-") || strings.HasPrefix(q, "debian-") || strings.HasPrefix(q, "ubuntu-") {
		if vs, err := s.store.DeviceVulns(ctx, 0); err == nil {
			found := map[string]*searchVuln{}
			var order []string
			for _, v := range vs {
				x := byID[v.DeviceID]
				if x == nil || !has(v.ID) {
					continue
				}
				f := found[v.ID]
				if f == nil {
					f = &searchVuln{ID: v.ID, Product: v.Product}
					found[v.ID] = f
					order = append(order, v.ID)
				}
				f.Devices = append(f.Devices, x)
			}
			for _, id := range order {
				if len(d.Vulns) < searchMax {
					d.Vulns = append(d.Vulns, *found[id])
				}
			}
		}
	}
	s.render(w, r, http.StatusOK, "search", &Page{Title: "Search", Data: d})
}
