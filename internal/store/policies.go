package store

import (
	"context"
	"encoding/json"
	"time"
)

// Policy is a named set of settings; Settings is decoded by the console.
type Policy struct {
	ID          int64
	CustomerID  *int64 // nil: a policy of the whole server
	Customer    string
	Name        string
	Description string
	Settings    json.RawMessage
	UpdatedBy   string
	UpdatedAt   time.Time
	Assigned    int // number of customers, sites and devices (lists only)
}

// Policies lists all policies by name.
func (s *Store) Policies(ctx context.Context) ([]Policy, error) {
	rows, err := s.db.Query(ctx, `SELECT p.id, p.customer_id, COALESCE(c.name, ''), p.name, p.description, p.settings, p.updated_by, p.updated_at,
		(SELECT count(*) FROM policy_assignments a WHERE a.policy_id=p.id) FROM policies p LEFT JOIN customers c ON c.id=p.customer_id ORDER BY lower(p.name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(&p.ID, &p.CustomerID, &p.Customer, &p.Name, &p.Description, &p.Settings, &p.UpdatedBy, &p.UpdatedAt, &p.Assigned); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Policy loads one policy.
func (s *Store) Policy(ctx context.Context, id int64) (*Policy, error) {
	var p Policy
	err := s.db.QueryRow(ctx, `SELECT p.id, p.customer_id, COALESCE(c.name, ''), p.name, p.description, p.settings, p.updated_by, p.updated_at FROM policies p LEFT JOIN customers c ON c.id=p.customer_id WHERE p.id=$1`, id).
		Scan(&p.ID, &p.CustomerID, &p.Customer, &p.Name, &p.Description, &p.Settings, &p.UpdatedBy, &p.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &p, nil
}

// SavePolicy adds (ID 0) or changes a policy.
func (s *Store) SavePolicy(ctx context.Context, p *Policy) error {
	p.UpdatedAt = s.now()
	if len(p.Settings) == 0 {
		p.Settings = json.RawMessage("{}")
	}
	var err error
	if p.ID == 0 {
		err = s.db.QueryRow(ctx, `INSERT INTO policies(name, description, settings, updated_by, updated_at, customer_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,
			p.Name, p.Description, p.Settings, p.UpdatedBy, p.UpdatedAt, p.CustomerID).Scan(&p.ID)
	} else {
		tag, e := s.db.Exec(ctx, `UPDATE policies SET name=$2, description=$3, settings=$4, updated_by=$5, updated_at=$6 WHERE id=$1`,
			p.ID, p.Name, p.Description, p.Settings, p.UpdatedBy, p.UpdatedAt)
		if err = e; err == nil && tag.RowsAffected() == 0 {
			err = ErrNotFound
		}
	}
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// DeletePolicy removes a policy and its assignments.
func (s *Store) DeletePolicy(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM policies WHERE id=$1`, id)
	return err
}

// Assignment ties a policy to a customer, site or device.
type Assignment struct {
	TargetType string // customer, site, device
	TargetID   int64
	PolicyID   int64
	PolicyName string
	Name       string // of the target, for pages
	AssignedBy string
	AssignedAt time.Time
}

// Assign gives a target a policy (replacing the one it had).
func (s *Store) Assign(ctx context.Context, targetType string, targetID, policyID int64, by string) error {
	_, err := s.db.Exec(ctx, `INSERT INTO policy_assignments(target_type, target_id, policy_id, assigned_by, assigned_at) VALUES($1,$2,$3,$4,$5)
		ON CONFLICT (target_type, target_id) DO UPDATE SET policy_id=EXCLUDED.policy_id, assigned_by=EXCLUDED.assigned_by, assigned_at=EXCLUDED.assigned_at`,
		targetType, targetID, policyID, by, s.now())
	return err
}

// Unassign removes the policy of a target.
func (s *Store) Unassign(ctx context.Context, targetType string, targetID int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM policy_assignments WHERE target_type=$1 AND target_id=$2`, targetType, targetID)
	return err
}

const assignmentCols = `a.target_type, a.target_id, a.policy_id, p.name,
	COALESCE(c.name, x.name, d.hostname, ''), a.assigned_by, a.assigned_at`

const assignmentJoins = ` FROM policy_assignments a JOIN policies p ON p.id=a.policy_id
	LEFT JOIN customers c ON a.target_type='customer' AND c.id=a.target_id
	LEFT JOIN sites x ON a.target_type='site' AND x.id=a.target_id
	LEFT JOIN devices d ON a.target_type='device' AND d.id=a.target_id`

func (s *Store) assignments(ctx context.Context, where string, args ...any) ([]Assignment, error) {
	rows, err := s.db.Query(ctx, `SELECT `+assignmentCols+assignmentJoins+where+` ORDER BY a.target_type, 5`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Assignment
	for rows.Next() {
		var a Assignment
		if err := rows.Scan(&a.TargetType, &a.TargetID, &a.PolicyID, &a.PolicyName, &a.Name, &a.AssignedBy, &a.AssignedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Assignments lists all assignments.
func (s *Store) Assignments(ctx context.Context) ([]Assignment, error) {
	return s.assignments(ctx, "")
}

// PolicyAssignments lists the targets of one policy.
func (s *Store) PolicyAssignments(ctx context.Context, policyID int64) ([]Assignment, error) {
	return s.assignments(ctx, " WHERE a.policy_id=$1", policyID)
}

// DeviceScope is where a device sits, for resolving its policies.
type DeviceScope struct {
	DeviceID   int64
	SiteID     int64
	CustomerID int64
	Hostname   string
	OS         string
}

// DeviceScopes lists every device with its site and customer.
func (s *Store) DeviceScopes(ctx context.Context) ([]DeviceScope, error) {
	rows, err := s.db.Query(ctx, `SELECT d.id, d.site_id, x.customer_id, d.hostname, COALESCE(d.os, '') FROM devices d JOIN sites x ON x.id=d.site_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceScope
	for rows.Next() {
		var d DeviceScope
		if err := rows.Scan(&d.DeviceID, &d.SiteID, &d.CustomerID, &d.Hostname, &d.OS); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Mark records that a policy did something (key) now.
func (s *Store) Mark(ctx context.Context, key string) error {
	_, err := s.db.Exec(ctx, `INSERT INTO policy_marks(key, marked_at) VALUES($1,$2) ON CONFLICT (key) DO UPDATE SET marked_at=EXCLUDED.marked_at`, key, s.now())
	return err
}

// Marked returns when key was marked last (zero if never).
func (s *Store) Marked(ctx context.Context, key string) (time.Time, error) {
	var t time.Time
	err := s.db.QueryRow(ctx, `SELECT marked_at FROM policy_marks WHERE key=$1`, key).Scan(&t)
	if err != nil {
		if notFound(err) == ErrNotFound {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	return t, nil
}

// MarkOnce marks key with the time at and reports whether it was not
// already marked at that time or later (a time slot fires once).
func (s *Store) MarkOnce(ctx context.Context, key string, at time.Time) (bool, error) {
	tag, err := s.db.Exec(ctx, `INSERT INTO policy_marks(key, marked_at) VALUES($1,$2)
		ON CONFLICT (key) DO UPDATE SET marked_at=EXCLUDED.marked_at WHERE policy_marks.marked_at < EXCLUDED.marked_at`, key, at)
	return tag.RowsAffected() == 1, err
}
