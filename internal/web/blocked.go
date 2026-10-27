package web

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

// Blocked programs of a policy: found in a device's inventory they open an
// alert, and those marked for removal are uninstalled silently (again after
// requiredRetry while they are still there).

// AlertBlocked is the alert of a blocked program.
const AlertBlocked = "blocked"

func init() {
	alertTitles[AlertBlocked] = "Blocked program installed"
	taskKinds["blocked.remove"] = taskBlockedRemove
}

// matchingApps lists the installed programs whose name contains match.
func matchingApps(inv *proto.Inventory, match string) []string {
	if inv == nil {
		return nil
	}
	m := strings.ToLower(strings.TrimSpace(match))
	var out []string
	for _, sw := range inv.Software {
		if m != "" && strings.Contains(strings.ToLower(sw.Name), m) {
			out = append(out, strings.TrimSpace(sw.Name+" "+sw.Version))
		}
	}
	return out
}

// removeBlocked starts the removal of the blocked programs of a device that
// are due (called with the required software).
func (s *Server) removeBlocked(ctx context.Context, d *store.Device, sw *SoftwarePolicy, policy string) {
	for _, b := range sw.Blocked {
		if !b.Remove || len(matchingApps(d.Inventory, b.Match)) == 0 {
			continue
		}
		key := "blocked:" + strconv.FormatInt(d.ID, 10) + ":" + strings.ToLower(b.Match)
		if t, err := s.store.Marked(ctx, key); err != nil || s.now().Sub(t) < requiredRetry {
			continue
		}
		if _, err := s.queueTask(ctx, d, "policy "+policy, "blocked.remove", "Remove blocked program %s", []string{b.Match}, blockedTask{Match: b.Match}); err != nil {
			s.log.Warn("policies: cannot queue a removal", "device", d.ID, "err", err)
			continue
		}
		_ = s.store.Mark(ctx, key)
	}
}

type blockedTask struct {
	Match string `json:"match"`
}

func taskBlockedRemove(s *Server, ctx context.Context, d *store.Device, t *store.DeviceTask) (taskOutcome, error) {
	var a blockedTask
	if err := taskArgs(t, &a); err != nil {
		return taskOutcome{}, err
	}
	var list proto.ProgramsResult
	if err := s.call(ctx, d.ID, t.CreatedBy, proto.KindPrograms, nil, &list, 2*time.Minute); err != nil {
		return taskOutcome{}, err
	}
	m := strings.ToLower(strings.TrimSpace(a.Match))
	var removed, failed, manual int
	for _, p := range list.Programs {
		if ctx.Err() != nil {
			return taskOutcome{}, ctx.Err()
		}
		if m == "" || !strings.Contains(strings.ToLower(p.Name), m) {
			continue
		}
		if !p.Silent {
			manual++
			continue
		}
		var res proto.UninstallResult
		if err := s.call(ctx, d.ID, t.CreatedBy, proto.KindUninstall, proto.Uninstall{Key: p.Key}, &res, 30*time.Minute); err != nil {
			failed++
			s.taskAudit(ctx, t, d, "software.uninstall", "blocked program %s on %q: removal failed: %v", p.Name, d.Hostname, err)
			continue
		}
		removed++
		s.taskAudit(ctx, t, d, "software.uninstall", "blocked program %s %s removed from %q (%s)", p.Name, p.Version, d.Hostname, res.Method)
	}
	s.requestInventory(ctx, d.ID)
	link := s.deviceURL(d, "/software")
	if removed+failed+manual == 0 {
		return outcome(true, link, "not installed"), nil
	}
	return outcome(failed+manual == 0, link, "%s removed, %s failed, %s cannot be removed silently", removed, failed, manual), nil
}

// blockedConditions are the alerts of blocked programs found in inventories.
func (s *Server) blockedConditions(ctx context.Context, pr *policyResolver) []store.Condition {
	var conds []store.Condition
	for id := range pr.scopes {
		sw, l := pr.software(id)
		if sw == nil || len(sw.Blocked) == 0 {
			continue
		}
		d, err := s.store.Device(ctx, id)
		if err != nil || d.Inventory == nil {
			continue
		}
		for _, b := range sw.Blocked {
			if found := matchingApps(d.Inventory, b.Match); len(found) > 0 {
				conds = append(conds, store.Condition{DeviceID: id, Kind: AlertBlocked, Key: strings.ToLower(b.Match), Severity: "warning",
					Message: fmt.Sprintf("%s (blocked by policy %s)", strings.Join(found, ", "), l.Policy.Name)})
			}
		}
	}
	return conds
}

// blockedState is a blocked program and what of it a device has.
type blockedState struct {
	App   BlockedApp
	Found []string
}
