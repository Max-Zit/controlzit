package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
)

// NetCheckState is the last result of a network check.
type NetCheckState struct {
	DeviceID     int64
	Name         string
	Kind         string
	Target       string
	OK           bool
	MS           int
	Error        string
	CertDays     int
	CheckedAt    time.Time
	FailingSince *time.Time
}

// SaveNetChecks stores the results of a device's checks; a failing check
// keeps the time it started failing, and checks no longer run are removed.
func (s *Store) SaveNetChecks(ctx context.Context, deviceID int64, checks []proto.NetCheck, results []proto.NetCheckResult) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	now := s.now()
	names := make([]string, 0, len(checks))
	for i, c := range checks {
		if i >= len(results) {
			break
		}
		r := results[i]
		names = append(names, c.Name)
		if _, err := tx.Exec(ctx, `INSERT INTO net_check_state(device_id, name, kind, target, ok, ms, error, cert_days, checked_at, failing_since)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9, CASE WHEN $5 THEN NULL ELSE $9::timestamptz END)
			ON CONFLICT (device_id, name) DO UPDATE SET kind=EXCLUDED.kind, target=EXCLUDED.target, ok=EXCLUDED.ok, ms=EXCLUDED.ms,
				error=EXCLUDED.error, cert_days=EXCLUDED.cert_days, checked_at=EXCLUDED.checked_at,
				failing_since=CASE WHEN EXCLUDED.ok THEN NULL ELSE COALESCE(net_check_state.failing_since, EXCLUDED.checked_at) END`,
			deviceID, c.Name, c.Kind, c.Target, r.OK, r.MS, r.Error, r.CertDays, now); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM net_check_state WHERE device_id=$1 AND NOT (name = ANY($2))`, deviceID, names); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ClearNetChecks removes the results of devices that no longer run checks.
func (s *Store) ClearNetChecks(ctx context.Context, keep []int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM net_check_state WHERE NOT (device_id = ANY($1))`, keep)
	return err
}

// NetChecks lists the check results, of one device or (0) all.
func (s *Store) NetChecks(ctx context.Context, deviceID int64) ([]NetCheckState, error) {
	rows, err := s.db.Query(ctx, `SELECT device_id, name, kind, target, ok, ms, error, cert_days, checked_at, failing_since
		FROM net_check_state WHERE $1 = 0 OR device_id = $1 ORDER BY device_id, name`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NetCheckState
	for rows.Next() {
		var c NetCheckState
		if err := rows.Scan(&c.DeviceID, &c.Name, &c.Kind, &c.Target, &c.OK, &c.MS, &c.Error, &c.CertDays, &c.CheckedAt, &c.FailingSince); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SaveDiskHealth stores the disk health a device reported.
func (s *Store) SaveDiskHealth(ctx context.Context, deviceID int64, h *proto.DiskHealth) error {
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `INSERT INTO device_disk_health(device_id, health, collected_at) VALUES($1,$2,$3)
		ON CONFLICT (device_id) DO UPDATE SET health=EXCLUDED.health, collected_at=EXCLUDED.collected_at`, deviceID, raw, s.now())
	return err
}

// DiskHealthState is a device's last disk health report.
type DiskHealthState struct {
	Health      proto.DiskHealth
	CollectedAt time.Time
}

// DiskHealth returns the last reports, of one device or (0) all.
func (s *Store) DiskHealth(ctx context.Context, deviceID int64) (map[int64]DiskHealthState, error) {
	rows, err := s.db.Query(ctx, `SELECT device_id, health, collected_at FROM device_disk_health WHERE $1 = 0 OR device_id = $1`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]DiskHealthState{}
	for rows.Next() {
		var id int64
		var raw []byte
		var h DiskHealthState
		if err := rows.Scan(&id, &raw, &h.CollectedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(raw, &h.Health)
		out[id] = h
	}
	return out, rows.Err()
}
