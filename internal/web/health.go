package web

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/store"
)

// Network checks of policies and the disk health of devices: collected
// from the agents and turned into alerts.

// NetCheckPolicy lists the checks the devices of a policy run.
type NetCheckPolicy struct {
	Checks []NetCheckRule `json:"checks"`
}

// NetCheckRule is a check and how long it may fail before an alert opens.
type NetCheckRule struct {
	proto.NetCheck
	FailMinutes int    `json:"fail_minutes"`
	Key         string `json:"-"` // the row of the form
}

func (n *NetCheckPolicy) validate() error {
	if len(n.Checks) > proto.MaxNetChecks {
		return fmt.Errorf("at most %d network checks", proto.MaxNetChecks)
	}
	seen := map[string]bool{}
	for _, c := range n.Checks {
		if err := c.Valid(); err != nil {
			return err
		}
		if c.FailMinutes < 1 || c.FailMinutes > 1440 {
			return errors.New("a network check may fail 1–1440 minutes before its alert")
		}
		if k := strings.ToLower(c.Name); seen[k] {
			return errors.New("each network check needs its own name")
		} else {
			seen[k] = true
		}
	}
	return nil
}

func (pr *policyResolver) netChecks(deviceID int64) (*NetCheckPolicy, *policyLevel) {
	if l := pr.part(deviceID, func(p *PolicySettings) bool { return p.NetChecks != nil }); l != nil {
		return l.Settings.NetChecks, l
	}
	return nil, nil
}

// Alert kinds of this file.
const (
	AlertNetCheck   = "netcheck"
	AlertCert       = "certificate"
	AlertDiskHealth = "diskhealth"
	AlertRAID       = "raid"
)

func init() {
	alertTitles[AlertNetCheck] = "Network check failed"
	alertTitles[AlertCert] = "Certificate expires soon"
	alertTitles[AlertDiskHealth] = "Disk health problem"
	alertTitles[AlertRAID] = "RAID array degraded"
}

// certWarnDays is when an expiring certificate of a web check alerts.
const certWarnDays = 14

// collectors keeps the runs of the network checks and the disk health from
// overlapping, and when each device was last asked for its disk health.
type collectors struct {
	mu        sync.Mutex
	netBusy   bool
	diskBusy  bool
	diskAsked map[int64]time.Time
}

// RunNetChecks asks the connected devices to run their policy's network
// checks (monitor loop, every minute; in the background).
func (s *Server) RunNetChecks(ctx context.Context) {
	pr, err := s.cachedPolicies(ctx)
	if err != nil {
		return
	}
	type job struct {
		id     int64
		checks []proto.NetCheck
	}
	var jobs []job
	var keep []int64
	for id := range pr.scopes {
		n, _ := pr.netChecks(id)
		if n == nil || len(n.Checks) == 0 {
			continue
		}
		keep = append(keep, id)
		if !s.Connected(id) {
			continue
		}
		j := job{id: id}
		for _, c := range n.Checks {
			j.checks = append(j.checks, c.NetCheck)
		}
		jobs = append(jobs, j)
	}
	_ = s.store.ClearNetChecks(ctx, keep)
	s.collect.mu.Lock()
	if s.collect.netBusy || len(jobs) == 0 {
		s.collect.mu.Unlock()
		return
	}
	s.collect.netBusy = true
	s.collect.mu.Unlock()
	go func() { // #nosec G118 -- outlives the monitor tick on purpose; own timeouts
		defer func() { s.collect.mu.Lock(); s.collect.netBusy = false; s.collect.mu.Unlock() }()
		ctx := context.Background()
		var wg sync.WaitGroup
		sem := make(chan struct{}, 16)
		for _, j := range jobs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				var res proto.NetCheckResults
				if err := s.call(ctx, j.id, "system", proto.KindNetCheck, proto.NetCheckRun{Checks: j.checks}, &res, 45*time.Second); err != nil {
					s.log.Debug("network checks", "device", j.id, "err", err)
					return
				}
				if err := s.store.SaveNetChecks(ctx, j.id, j.checks, res.Results); err != nil {
					s.log.Warn("network checks: cannot store", "device", j.id, "err", err)
				}
			}()
		}
		wg.Wait()
	}()
}

// diskHealthEvery is how often a device reports its disk health.
const diskHealthEvery = time.Hour

// RunDiskHealth asks connected devices for their disk health once an hour
// (monitor loop; in the background).
func (s *Server) RunDiskHealth(ctx context.Context) {
	s.collect.mu.Lock()
	if s.collect.diskBusy {
		s.collect.mu.Unlock()
		return
	}
	if s.collect.diskAsked == nil {
		s.collect.diskAsked = map[int64]time.Time{}
	}
	now := s.now()
	var due []int64
	for _, id := range s.hub.connectedIDs() {
		if now.Sub(s.collect.diskAsked[id]) >= diskHealthEvery {
			s.collect.diskAsked[id] = now
			due = append(due, id)
		}
	}
	if len(due) == 0 {
		s.collect.mu.Unlock()
		return
	}
	s.collect.diskBusy = true
	s.collect.mu.Unlock()
	go func() { // #nosec G118 -- outlives the monitor tick on purpose; own timeouts
		defer func() { s.collect.mu.Lock(); s.collect.diskBusy = false; s.collect.mu.Unlock() }()
		ctx := context.Background()
		var wg sync.WaitGroup
		sem := make(chan struct{}, 8)
		for _, id := range due {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				if !s.collectDiskHealth(ctx, id) {
					// An older agent, or busy: ask again in 10 minutes.
					s.collect.mu.Lock()
					s.collect.diskAsked[id] = s.now().Add(10*time.Minute - diskHealthEvery)
					s.collect.mu.Unlock()
				}
			}()
		}
		wg.Wait()
	}()
}

// healthConditions are the alerts of failing network checks, expiring
// certificates and disk or RAID problems.
func (s *Server) healthConditions(ctx context.Context, pr *policyResolver, rules map[int64]MonitoringSettings) []store.Condition {
	var conds []store.Condition
	now := s.now()
	checks, err := s.store.NetChecks(ctx, 0)
	if err == nil {
		for _, c := range checks {
			n, _ := pr.netChecks(c.DeviceID)
			if n == nil {
				continue
			}
			for _, rule := range n.Checks {
				if rule.Name != c.Name {
					continue
				}
				if !c.OK && c.FailingSince != nil && now.Sub(*c.FailingSince) >= time.Duration(rule.FailMinutes)*time.Minute {
					conds = append(conds, store.Condition{DeviceID: c.DeviceID, Kind: AlertNetCheck, Key: c.Name, Severity: "critical",
						Message: fmt.Sprintf("%s (%s %s): %s", c.Name, c.Kind, c.Target, c.Error)})
				}
				if c.Kind == proto.NetHTTP && c.CertDays != 0 && c.CertDays < certWarnDays {
					conds = append(conds, store.Condition{DeviceID: c.DeviceID, Kind: AlertCert, Key: c.Name, Severity: "warning",
						Message: fmt.Sprintf("the certificate of %s expires in %d days", c.Target, c.CertDays)})
				}
			}
		}
	}
	health, err := s.store.DiskHealth(ctx, 0)
	if err != nil {
		return conds
	}
	for id, h := range health {
		r, ok := rules[id]
		if !ok || r.DiskHealthOff {
			continue
		}
		for _, d := range h.Health.Disks {
			sev := ""
			switch d.Health {
			case proto.HealthFailing:
				sev = "critical"
			case proto.HealthWarning:
				sev = "warning"
			}
			if sev == "" {
				continue
			}
			msg := d.Model
			if d.Serial != "" {
				msg += " (" + d.Serial + ")"
			}
			msg += ": " + d.Health
			if d.Status != "" && d.Status != "OK" {
				msg += ", " + d.Status
			}
			if d.Errors > 0 {
				msg += fmt.Sprintf(", %d errors or bad sectors", d.Errors)
			}
			conds = append(conds, store.Condition{DeviceID: id, Kind: AlertDiskHealth, Key: d.Model + " " + d.Serial, Severity: sev, Message: msg})
		}
		for _, a := range h.Health.Arrays {
			if a.Health != proto.HealthWarning && a.Health != proto.HealthFailing {
				continue
			}
			sev := "warning"
			if a.Health == proto.HealthFailing {
				sev = "critical"
			}
			conds = append(conds, store.Condition{DeviceID: id, Kind: AlertRAID, Key: a.Name, Severity: sev,
				Message: strings.TrimSpace(a.Name + " " + a.Level + ": " + a.State)})
		}
	}
	return conds
}

// collectDiskHealth asks a device for its disk health and stores it.
func (s *Server) collectDiskHealth(ctx context.Context, id int64) bool {
	var h proto.DiskHealth
	if err := s.call(ctx, id, "system", proto.KindDiskHealth, nil, &h, 3*time.Minute); err != nil {
		s.log.Debug("disk health", "device", id, "err", err)
		return false
	}
	if len(h.Disks) > 64 {
		h.Disks = h.Disks[:64]
	}
	if err := s.store.SaveDiskHealth(ctx, id, &h); err != nil {
		s.log.Warn("disk health: cannot store", "device", id, "err", err)
		return false
	}
	return true
}
