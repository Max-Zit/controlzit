package store

import (
	"context"
	"time"
)

// MonitorResult is the last result of a monitor on a device.
type MonitorResult struct {
	DeviceID  int64
	Kind      string // event, process
	Key       string // the rule's name, the process name
	OK        bool   // events under the limit, the process runs
	Count     int
	Error     string
	CheckedAt time.Time
}

// SaveMonitorResults replaces the results of a device.
func (s *Store) SaveMonitorResults(ctx context.Context, deviceID int64, list []MonitorResult) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM monitor_state WHERE device_id=$1`, deviceID); err != nil {
		return err
	}
	now := s.now()
	for _, m := range list {
		if _, err := tx.Exec(ctx, `INSERT INTO monitor_state (device_id, kind, key, ok, count, error, checked_at) VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (device_id, kind, key) DO UPDATE SET ok=excluded.ok, count=excluded.count, error=excluded.error, checked_at=excluded.checked_at`,
			deviceID, m.Kind, m.Key, m.OK, m.Count, m.Error, now); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ClearMonitorResults deletes the results of the devices not in keep (their
// policy has no monitors any more).
func (s *Store) ClearMonitorResults(ctx context.Context, keep []int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM monitor_state WHERE NOT (device_id = ANY($1))`, keep)
	return err
}

// MonitorResults returns the results of a device (0: all devices).
func (s *Store) MonitorResults(ctx context.Context, deviceID int64) ([]MonitorResult, error) {
	rows, err := s.db.Query(ctx, `SELECT device_id, kind, key, ok, count, error, checked_at FROM monitor_state
		WHERE $1 = 0 OR device_id = $1 ORDER BY device_id, kind, key`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MonitorResult
	for rows.Next() {
		var m MonitorResult
		if err := rows.Scan(&m.DeviceID, &m.Kind, &m.Key, &m.OK, &m.Count, &m.Error, &m.CheckedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
