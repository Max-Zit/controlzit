package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
)

// SaveMetrics stores the metrics of a heartbeat and a history sample.
func (s *Store) SaveMetrics(ctx context.Context, id int64, m *proto.Metrics) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	now := s.now()
	mem := 0.0
	if m.MemTotal > 0 {
		mem = float64(m.MemUsed) / float64(m.MemTotal) * 100
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE devices SET metrics=$2, metrics_at=$3 WHERE id=$1`, id, raw, now); err != nil {
		return err
	}
	if m.StoppedAuto != nil {
		if _, err := tx.Exec(ctx, `UPDATE devices SET stopped_auto=$2 WHERE id=$1`, id, m.StoppedAuto); err != nil {
			return err
		}
	}
	if m.Security != nil {
		sec, _ := json.Marshal(m.Security)
		if _, err := tx.Exec(ctx, `UPDATE devices SET security=$2 WHERE id=$1`, id, sec); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO device_samples(device_id, at, cpu, mem) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, id, now, m.CPU, mem); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// PurgeSamples deletes history older than keep.
func (s *Store) PurgeSamples(ctx context.Context, keep time.Duration) error {
	_, err := s.db.Exec(ctx, `DELETE FROM device_samples WHERE at < $1`, s.now().Add(-keep))
	return err
}

// MonitorState is what the alert rules look at for one device.
type MonitorState struct {
	ID          int64
	CustomerID  int64
	Hostname    string
	Customer    string
	Site        string
	Connected   bool
	LastSeen    *time.Time
	BootTime    *time.Time
	Metrics     *proto.Metrics
	Security    *proto.SecurityState
	StoppedAuto []string
	// AvgCPU and AvgMem over the rule window, with the number of samples.
	AvgCPU, AvgMem float64
	Samples        int
}

// MonitorStates loads every device with its averages over window.
func (s *Store) MonitorStates(ctx context.Context, cpuWindow, memWindow time.Duration) ([]MonitorState, error) {
	now := s.now()
	rows, err := s.db.Query(ctx, `SELECT d.id, x.customer_id, d.hostname, c.name, x.name, d.connected, d.last_seen_at, d.boot_time,
		d.metrics, d.security, d.stopped_auto,
		COALESCE((SELECT avg(cpu) FROM device_samples WHERE device_id=d.id AND at > $1), 0),
		(SELECT count(*) FROM device_samples WHERE device_id=d.id AND at > $1),
		COALESCE((SELECT avg(mem) FROM device_samples WHERE device_id=d.id AND at > $2), 0)
		FROM devices d JOIN sites x ON x.id=d.site_id JOIN customers c ON c.id=x.customer_id ORDER BY d.id`,
		now.Add(-cpuWindow), now.Add(-memWindow))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MonitorState
	for rows.Next() {
		var m MonitorState
		var mraw, sraw []byte
		if err := rows.Scan(&m.ID, &m.CustomerID, &m.Hostname, &m.Customer, &m.Site, &m.Connected, &m.LastSeen, &m.BootTime,
			&mraw, &sraw, &m.StoppedAuto, &m.AvgCPU, &m.Samples, &m.AvgMem); err != nil {
			return nil, err
		}
		if mraw != nil {
			m.Metrics = &proto.Metrics{}
			_ = json.Unmarshal(mraw, m.Metrics)
		}
		if sraw != nil {
			m.Security = &proto.SecurityState{}
			_ = json.Unmarshal(sraw, m.Security)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Alert is an open or past alert.
type Alert struct {
	ID         int64
	DeviceID   int64
	Hostname   string
	CustomerID int64
	Customer   string
	Site       string
	Kind       string
	Key        string
	Severity   string
	Message    string
	OpenedAt   time.Time
	LastSeen   time.Time
	ResolvedAt *time.Time
	AckedBy    *string
	AckedAt    *time.Time
}

// Condition is an alert a rule found now.
type Condition struct {
	DeviceID int64
	Kind     string
	Key      string
	Severity string
	Message  string
}

// SyncAlerts opens alerts for new conditions, refreshes the ones that
// still hold and resolves the ones that are gone. It returns the alerts it
// opened and resolved (for notifications). Open alerts of the devices in
// keep stay open even without a condition (their data is out of date).
func (s *Store) SyncAlerts(ctx context.Context, conds []Condition, keep map[int64]bool) (opened, resolved []Alert, err error) {
	now := s.now()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7263003)`); err != nil {
		return nil, nil, err
	}
	seen := map[int64]bool{}
	for _, c := range conds {
		var id int64
		var isNew bool
		err := tx.QueryRow(ctx, `INSERT INTO alerts(device_id, kind, key, severity, message, opened_at, last_seen)
			VALUES($1,$2,$3,$4,$5,$6,$6)
			ON CONFLICT (device_id, kind, key) WHERE resolved_at IS NULL
			DO UPDATE SET last_seen=EXCLUDED.last_seen, message=EXCLUDED.message, severity=EXCLUDED.severity
			RETURNING id, (xmax = 0)`, c.DeviceID, c.Kind, c.Key, c.Severity, c.Message, now).Scan(&id, &isNew)
		if err != nil {
			return nil, nil, err
		}
		seen[id] = true
		if isNew {
			opened = append(opened, Alert{ID: id, DeviceID: c.DeviceID, Kind: c.Kind, Key: c.Key, Severity: c.Severity, Message: c.Message, OpenedAt: now})
		}
	}
	rows, err := tx.Query(ctx, `SELECT id, device_id, kind, key, severity, message, opened_at FROM alerts WHERE resolved_at IS NULL`)
	if err != nil {
		return nil, nil, err
	}
	var gone []Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.DeviceID, &a.Kind, &a.Key, &a.Severity, &a.Message, &a.OpenedAt); err != nil {
			rows.Close()
			return nil, nil, err
		}
		if !seen[a.ID] && !keep[a.DeviceID] {
			gone = append(gone, a)
		}
	}
	rows.Close()
	for _, a := range gone {
		if _, err := tx.Exec(ctx, `UPDATE alerts SET resolved_at=$2 WHERE id=$1`, a.ID, now); err != nil {
			return nil, nil, err
		}
		t := now
		a.ResolvedAt = &t
		resolved = append(resolved, a)
	}
	return opened, resolved, tx.Commit(ctx)
}

// AlertFilter selects alerts.
type AlertFilter struct {
	DeviceID int64
	Open     bool // only open alerts
	Limit    int
}

// Alerts lists alerts the user may see, newest first.
func (s *Store) Alerts(ctx context.Context, u *User, f AlertFilter) ([]Alert, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	rows, err := s.db.Query(ctx, `SELECT a.id, a.device_id, d.hostname, x.customer_id, c.name, x.name, a.kind, a.key, a.severity, a.message,
		a.opened_at, a.last_seen, a.resolved_at, a.acked_by, a.acked_at
		FROM alerts a JOIN devices d ON d.id=a.device_id JOIN sites x ON x.id=d.site_id JOIN customers c ON c.id=x.customer_id
		WHERE ($1 OR x.customer_id IN (SELECT customer_id FROM user_customers WHERE user_id=$2))
		  AND ($3 = 0 OR a.device_id=$3) AND (NOT $4 OR a.resolved_at IS NULL)
		ORDER BY (a.resolved_at IS NULL) DESC, CASE a.severity WHEN 'critical' THEN 0 ELSE 1 END, a.opened_at DESC LIMIT $5`,
		u.IsAdmin() || u.AllCustomers, u.ID, f.DeviceID, f.Open, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.DeviceID, &a.Hostname, &a.CustomerID, &a.Customer, &a.Site, &a.Kind, &a.Key, &a.Severity, &a.Message,
			&a.OpenedAt, &a.LastSeen, &a.ResolvedAt, &a.AckedBy, &a.AckedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// OpenAlertCount counts open, unacknowledged alerts the user may see.
func (s *Store) OpenAlertCount(ctx context.Context, u *User) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM alerts a JOIN devices d ON d.id=a.device_id JOIN sites x ON x.id=d.site_id
		WHERE a.resolved_at IS NULL AND a.acked_at IS NULL
		  AND ($1 OR x.customer_id IN (SELECT customer_id FROM user_customers WHERE user_id=$2))`, u.IsAdmin() || u.AllCustomers, u.ID).Scan(&n)
	return n, err
}

// AckAlert marks an open alert as seen by a user.
func (s *Store) AckAlert(ctx context.Context, id int64, user string) (*Alert, error) {
	a := &Alert{ID: id}
	err := s.db.QueryRow(ctx, `UPDATE alerts SET acked_by=$2, acked_at=$3 WHERE id=$1 AND resolved_at IS NULL AND acked_at IS NULL
		RETURNING device_id, kind, key, message`, id, user, s.now()).Scan(&a.DeviceID, &a.Kind, &a.Key, &a.Message)
	return a, notFound(err)
}

// AlertDevice returns the customer of an alert's device (permission checks).
func (s *Store) AlertDevice(ctx context.Context, id int64) (deviceID, customerID int64, err error) {
	err = s.db.QueryRow(ctx, `SELECT a.device_id, x.customer_id FROM alerts a JOIN devices d ON d.id=a.device_id JOIN sites x ON x.id=d.site_id WHERE a.id=$1`, id).
		Scan(&deviceID, &customerID)
	return deviceID, customerID, notFound(err)
}

// MarkNotified records that the alert email went out.
func (s *Store) MarkNotified(ctx context.Context, ids []int64) error {
	_, err := s.db.Exec(ctx, `UPDATE alerts SET notified=true WHERE id = ANY($1)`, ids)
	return err
}

// DeviceMetrics returns the latest metrics of a device.
func (s *Store) DeviceMetrics(ctx context.Context, id int64) (*proto.Metrics, *time.Time, []string, error) {
	var raw []byte
	var at *time.Time
	var stopped []string
	err := s.db.QueryRow(ctx, `SELECT metrics, metrics_at, stopped_auto FROM devices WHERE id=$1`, id).Scan(&raw, &at, &stopped)
	if err != nil {
		return nil, nil, nil, notFound(err)
	}
	if raw == nil {
		return nil, at, stopped, nil
	}
	m := &proto.Metrics{}
	if err := json.Unmarshal(raw, m); err != nil {
		return nil, at, stopped, nil
	}
	return m, at, stopped, nil
}
