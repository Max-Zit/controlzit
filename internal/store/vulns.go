package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
)

// VulnSource returns cached vulnerability data (zero time: none).
func (s *Store) VulnSource(ctx context.Context, key string, v any) (time.Time, error) {
	var raw []byte
	var at time.Time
	err := s.db.QueryRow(ctx, `SELECT data, fetched_at FROM vuln_sources WHERE key=$1`, key).Scan(&raw, &at)
	if err != nil {
		if notFound(err) == ErrNotFound {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	return at, json.Unmarshal(raw, v)
}

// SaveVulnSource caches vulnerability data.
func (s *Store) SaveVulnSource(ctx context.Context, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `INSERT INTO vuln_sources(key, data, fetched_at) VALUES($1,$2,$3)
		ON CONFLICT (key) DO UPDATE SET data=EXCLUDED.data, fetched_at=EXCLUDED.fetched_at`, key, raw, s.now())
	return err
}

// VulnDetails returns the cached details of vulnerabilities fetched after
// since, by ID.
func (s *Store) VulnDetails(ctx context.Context, ids []string, since time.Time) (map[string]json.RawMessage, error) {
	rows, err := s.db.Query(ctx, `SELECT id, data FROM vuln_details WHERE id = ANY($1) AND fetched_at > $2`, ids, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]json.RawMessage{}
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		out[id] = raw
	}
	return out, rows.Err()
}

// SaveVulnDetail caches the details of a vulnerability.
func (s *Store) SaveVulnDetail(ctx context.Context, id string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `INSERT INTO vuln_details(id, data, fetched_at) VALUES($1,$2,$3)
		ON CONFLICT (id) DO UPDATE SET data=EXCLUDED.data, fetched_at=EXCLUDED.fetched_at`, id, raw, s.now())
	return err
}

// DeviceVuln is a vulnerability found on a device.
type DeviceVuln struct {
	DeviceID   int64
	Hostname   string
	CustomerID int64
	ID         string
	Product    string
	Version    string
	Severity   string
	Score      float64
	Summary    string
	Source     string
	Fix        string // the fixing version, "none" (no fix yet) or empty (not known)
}

// ReplaceDeviceVulns stores the findings of a scan for a device.
func (s *Store) ReplaceDeviceVulns(ctx context.Context, deviceID int64, list []DeviceVuln) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM device_vulns WHERE device_id=$1`, deviceID); err != nil {
		return err
	}
	for _, v := range list {
		if _, err := tx.Exec(ctx, `INSERT INTO device_vulns(device_id, vuln_id, product, version, severity, score, summary, source, fix)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`, deviceID, v.ID, clip(v.Product, 200), clip(v.Version, 100), v.Severity, v.Score, clip(v.Summary, 400), v.Source, clip(v.Fix, 100)); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// DeviceVulns lists the findings, of one device or (0) all, worst first.
func (s *Store) DeviceVulns(ctx context.Context, deviceID int64) ([]DeviceVuln, error) {
	rows, err := s.db.Query(ctx, `SELECT v.device_id, d.hostname, x.customer_id, v.vuln_id, v.product, v.version, v.severity, v.score, v.summary, v.source, v.fix
		FROM device_vulns v JOIN devices d ON d.id=v.device_id JOIN sites x ON x.id=d.site_id
		WHERE $1 = 0 OR v.device_id = $1 ORDER BY v.score DESC, v.vuln_id DESC`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceVuln
	for rows.Next() {
		var v DeviceVuln
		if err := rows.Scan(&v.DeviceID, &v.Hostname, &v.CustomerID, &v.ID, &v.Product, &v.Version, &v.Severity, &v.Score, &v.Summary, &v.Source, &v.Fix); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Inventories returns the last inventory of every device that has one.
func (s *Store) Inventories(ctx context.Context) (map[int64]*proto.Inventory, error) {
	rows, err := s.db.Query(ctx, `SELECT id, inventory FROM devices WHERE inventory IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]*proto.Inventory{}
	for rows.Next() {
		var id int64
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		var inv proto.Inventory
		if json.Unmarshal(raw, &inv) == nil {
			out[id] = &inv
		}
	}
	return out, rows.Err()
}
