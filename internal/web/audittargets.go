package web

import (
	"context"
	"strconv"
	"strings"
)

// The audit log stores targets as "device:9", "site:2", "user:pera" …
// The page shows them as names with a link (customer / site / device).
// Records that are gone show what the target was, with a note.

type auditTarget struct {
	Label string
	URL   string
	Gone  bool
}

// auditTargets resolves the targets of one page of the audit log.
func (s *Server) auditTargets(ctx context.Context, raw []string) map[string]auditTarget {
	out := map[string]auditTarget{}
	for _, t := range raw {
		if _, done := out[t]; done || t == "" {
			continue
		}
		kind, ref, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		id, _ := strconv.ParseInt(ref, 10, 64)
		switch kind {
		case "device":
			if d, err := s.store.Device(ctx, id); err == nil {
				out[t] = auditTarget{Label: d.Customer + " / " + d.Site + " / " + d.Hostname, URL: "/devices/" + ref}
			} else {
				out[t] = auditTarget{Label: "#" + ref, Gone: true}
			}
		case "site":
			if x, err := s.store.Site(ctx, id); err == nil {
				out[t] = auditTarget{Label: x.Customer + " / " + x.Name, URL: "/sites/" + ref}
			} else {
				out[t] = auditTarget{Label: "#" + ref, Gone: true}
			}
		case "customer":
			if c, err := s.store.Customer(ctx, id); err == nil {
				out[t] = auditTarget{Label: c.Name, URL: "/customers/" + ref}
			} else {
				out[t] = auditTarget{Label: "#" + ref, Gone: true}
			}
		case "script":
			if x, err := s.store.LibScript(ctx, id); err == nil {
				out[t] = auditTarget{Label: x.Name, URL: "/scripts/" + ref}
			} else {
				out[t] = auditTarget{Label: "#" + ref, Gone: true}
			}
		case "job":
			if j, err := s.store.Job(ctx, id); err == nil {
				out[t] = auditTarget{Label: j.Name, URL: "/jobs/" + ref}
			} else {
				out[t] = auditTarget{Label: "#" + ref, Gone: true}
			}
		case "user":
			out[t] = auditTarget{Label: ref} // the username itself
		}
	}
	return out
}

// Target is the display of an audit target (the raw text when unknown).
func (d *auditData) Target(raw string) auditTarget {
	if t, ok := d.Targets[raw]; ok {
		return t
	}
	return auditTarget{Label: raw}
}

// TargetKind is the kind of an audit target ("device", "site" …).
func (d *auditData) TargetKind(raw string) string {
	kind, _, _ := strings.Cut(raw, ":")
	return kind
}

// TargetKindLabel names the kind of a target (a catalog key).
func (d *auditData) TargetKindLabel(raw string) string {
	return map[string]string{"device": "Device", "site": "Site", "customer": "Customer", "script": "Script",
		"job": "Job", "user": "User", "settings": "Settings"}[d.TargetKind(raw)]
}
