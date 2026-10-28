package store

import (
	"context"
	"time"
)

// RollupMetrics writes the hourly summaries of the samples from the hour
// that holds from up to now (the current hour is rewritten until it ends),
// and the used space of each drive of the devices that reported in the
// last 15 minutes for the current hour.
func (s *Store) RollupMetrics(ctx context.Context, from time.Time) error {
	now := s.now()
	if _, err := s.db.Exec(ctx, `INSERT INTO device_hourly (device_id, hour, cpu_avg, cpu_max, mem_avg, mem_max, rx, tx, samples)
		SELECT device_id, date_trunc('hour', at), avg(cpu), max(cpu), avg(mem), max(mem), avg(rx), avg(tx), count(*)
		FROM device_samples WHERE at >= date_trunc('hour', $1::timestamptz) GROUP BY 1, 2
		ON CONFLICT (device_id, hour) DO UPDATE SET cpu_avg=excluded.cpu_avg, cpu_max=excluded.cpu_max, mem_avg=excluded.mem_avg,
			mem_max=excluded.mem_max, rx=excluded.rx, tx=excluded.tx, samples=excluded.samples`, from); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `INSERT INTO device_disk_hourly (device_id, hour, drive, size, free)
		SELECT d.id, date_trunc('hour', $1::timestamptz), left(x->>'drive', 100), (x->>'size')::bigint, (x->>'free')::bigint
		FROM devices d, jsonb_array_elements(CASE WHEN jsonb_typeof(d.metrics->'disks')='array' THEN d.metrics->'disks' ELSE '[]'::jsonb END) x
		WHERE d.metrics_at > $1::timestamptz - interval '15 minutes' AND (x->>'size')::bigint > 0 AND x->>'drive' <> ''
		ON CONFLICT (device_id, drive, hour) DO UPDATE SET size=excluded.size, free=excluded.free`, now)
	return err
}

// PurgeHistory deletes hourly summaries older than keep.
func (s *Store) PurgeHistory(ctx context.Context, keep time.Duration) error {
	before := s.now().Add(-keep)
	if _, err := s.db.Exec(ctx, `DELETE FROM device_hourly WHERE hour < $1`, before); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `DELETE FROM device_disk_hourly WHERE hour < $1`, before)
	return err
}

// LoadPoint is the load of a device over one chart step.
type LoadPoint struct {
	At             time.Time
	CPUAvg, CPUMax float64
	MemAvg, MemMax float64
	// Rx and Tx are bytes per second; nil when the agent sent none.
	Rx, Tx *float64
}

// LoadHistory returns the load of a device since from in steps of step:
// from the minute samples when they reach back far enough (7 days),
// otherwise from the hourly summaries.
func (s *Store) LoadHistory(ctx context.Context, deviceID int64, from time.Time, step time.Duration) ([]LoadPoint, error) {
	secs := max(int64(step/time.Second), 60)
	q := `SELECT to_timestamp(floor(extract(epoch FROM at) / $3) * $3) AS t, avg(cpu), max(cpu), avg(mem), max(mem), avg(rx), avg(tx)
		FROM device_samples WHERE device_id=$1 AND at >= $2 GROUP BY t ORDER BY t`
	if s.now().Sub(from) > 7*24*time.Hour {
		q = `SELECT to_timestamp(floor(extract(epoch FROM hour) / $3) * $3) AS t, sum(cpu_avg*samples)/sum(samples), max(cpu_max),
			sum(mem_avg*samples)/sum(samples), max(mem_max), avg(rx), avg(tx)
			FROM device_hourly WHERE device_id=$1 AND hour >= $2 GROUP BY t ORDER BY t`
	}
	rows, err := s.db.Query(ctx, q, deviceID, from, secs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LoadPoint
	for rows.Next() {
		var p LoadPoint
		if err := rows.Scan(&p.At, &p.CPUAvg, &p.CPUMax, &p.MemAvg, &p.MemMax, &p.Rx, &p.Tx); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DiskPoint is the space of a drive at one hour.
type DiskPoint struct {
	At         time.Time
	Size, Free int64
}

// DiskHistory returns the hourly space of each drive of a device since from,
// in steps of step (the last value of each step).
func (s *Store) DiskHistory(ctx context.Context, deviceID int64, from time.Time, step time.Duration) (map[string][]DiskPoint, error) {
	secs := max(int64(step/time.Second), 3600)
	rows, err := s.db.Query(ctx, `SELECT DISTINCT ON (drive, t) drive, to_timestamp(floor(extract(epoch FROM hour) / $3) * $3) AS t, size, free
		FROM device_disk_hourly WHERE device_id=$1 AND hour >= $2 ORDER BY drive, t, hour DESC`, deviceID, from, secs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]DiskPoint{}
	for rows.Next() {
		var drive string
		var p DiskPoint
		if err := rows.Scan(&drive, &p.At, &p.Size, &p.Free); err != nil {
			return nil, err
		}
		out[drive] = append(out[drive], p)
	}
	return out, rows.Err()
}

// DiskTrend is how fast the used space of a drive grew over the forecast
// window, with its space at the last hour.
type DiskTrend struct {
	DeviceID   int64
	Drive      string
	Size, Free int64
	// GrowthPerDay is the linear growth of the used space in bytes per day.
	GrowthPerDay float64
	Span         time.Duration // between the first and the last hour
	Points       int
}

// DiskTrends fits a line through the used space of each drive since from.
func (s *Store) DiskTrends(ctx context.Context, from time.Time) ([]DiskTrend, error) {
	rows, err := s.db.Query(ctx, `SELECT device_id, drive,
		(array_agg(size ORDER BY hour DESC))[1], (array_agg(free ORDER BY hour DESC))[1],
		COALESCE(regr_slope((size - free)::float8, extract(epoch FROM hour)), 0) * 86400,
		extract(epoch FROM max(hour) - min(hour)), count(*)
		FROM device_disk_hourly WHERE hour >= $1 GROUP BY device_id, drive`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DiskTrend
	for rows.Next() {
		var t DiskTrend
		var span float64
		if err := rows.Scan(&t.DeviceID, &t.Drive, &t.Size, &t.Free, &t.GrowthPerDay, &span, &t.Points); err != nil {
			return nil, err
		}
		t.Span = time.Duration(span * float64(time.Second))
		out = append(out, t)
	}
	return out, rows.Err()
}
