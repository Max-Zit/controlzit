package store

import (
	"context"
	"strconv"
	"time"
)

// Counted is a name with a number (report tables).
type Counted struct {
	Name  string
	Count int
}

// AlertStats summarizes the alerts of devices since a time.
type AlertStats struct {
	Opened    int       // opened in the period
	Critical  int       // of them critical
	OpenNow   int       // still open
	ByKind    []Counted // opened in the period, by kind
	ByDevice  []Counted // opened in the period, by hostname (top 10)
	Resolved  int       // opened and resolved in the period
	MeanHours float64   // mean time until resolved (resolved ones)
}

// ReportAlerts returns the alert statistics of the devices since t.
func (s *Store) ReportAlerts(ctx context.Context, devices []int64, since time.Time) (*AlertStats, error) {
	st := &AlertStats{}
	if err := s.db.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE severity='critical'),
		count(*) FILTER (WHERE resolved_at IS NOT NULL),
		COALESCE(avg(EXTRACT(EPOCH FROM resolved_at - opened_at)) FILTER (WHERE resolved_at IS NOT NULL), 0) / 3600
		FROM alerts WHERE device_id = ANY($1) AND opened_at >= $2`, devices, since).Scan(&st.Opened, &st.Critical, &st.Resolved, &st.MeanHours); err != nil {
		return nil, err
	}
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM alerts WHERE device_id = ANY($1) AND resolved_at IS NULL`, devices).Scan(&st.OpenNow); err != nil {
		return nil, err
	}
	var err error
	if st.ByKind, err = s.counted(ctx, `SELECT kind, count(*) FROM alerts WHERE device_id = ANY($1) AND opened_at >= $2 GROUP BY kind ORDER BY 2 DESC, 1`, devices, since); err != nil {
		return nil, err
	}
	st.ByDevice, err = s.counted(ctx, `SELECT d.hostname, count(*) FROM alerts a JOIN devices d ON d.id=a.device_id
		WHERE a.device_id = ANY($1) AND a.opened_at >= $2 GROUP BY d.hostname ORDER BY 2 DESC, 1 LIMIT 10`, devices, since)
	return st, err
}

// ReportActivity counts audit actions on the devices since t (remote
// desktop sessions, scripts, file transfers …).
func (s *Store) ReportActivity(ctx context.Context, devices []int64, since time.Time) (map[string]int, error) {
	targets := make([]string, 0, len(devices))
	for _, id := range devices {
		targets = append(targets, "device:"+strconv.FormatInt(id, 10))
	}
	rows, err := s.db.Query(ctx, `SELECT action, count(*) FROM audit_log WHERE at >= $1 AND target = ANY($2) GROUP BY action`, since, targets)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var a string
		var n int
		if err := rows.Scan(&a, &n); err != nil {
			return nil, err
		}
		out[a] = n
	}
	return out, rows.Err()
}

func (s *Store) counted(ctx context.Context, q string, args ...any) ([]Counted, error) {
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Counted
	for rows.Next() {
		var c Counted
		if err := rows.Scan(&c.Name, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// OpenAlertsByDevice counts the open alerts of every device.
func (s *Store) OpenAlertsByDevice(ctx context.Context) (map[int64]int, error) {
	rows, err := s.db.Query(ctx, `SELECT device_id, count(*) FROM alerts WHERE resolved_at IS NULL GROUP BY device_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int{}
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// MeanMinutes is the mean time until resolved in whole minutes.
func (a *AlertStats) MeanMinutes() int { return int(a.MeanHours*60 + 0.5) }
