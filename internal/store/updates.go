package store

import (
	"context"
	"time"
)

// Seen is an update or a program version as the server saw it.
type Seen struct {
	ID      string
	Version string
}

// FirstSeen records the items of a source that are new and returns when each
// was first seen (key: ID + "\x00" + Version).
func (s *Store) FirstSeen(ctx context.Context, source string, items []Seen) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	if len(items) == 0 {
		return out, nil
	}
	ids, versions := make([]string, len(items)), make([]string, len(items))
	for i, x := range items {
		ids[i], versions[i] = x.ID, x.Version
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO update_first_seen(source, id, version, first_seen)
		SELECT $1, i, v, $4 FROM unnest($2::text[], $3::text[]) AS t(i, v) ON CONFLICT DO NOTHING`, source, ids, versions, s.now()); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT f.id, f.version, f.first_seen FROM update_first_seen f
		JOIN unnest($2::text[], $3::text[]) AS t(i, v) ON f.id=t.i AND f.version=t.v WHERE f.source=$1`, source, ids, versions)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, v string
		var t time.Time
		if err := rows.Scan(&id, &v, &t); err != nil {
			return nil, err
		}
		out[id+"\x00"+v] = t
	}
	return out, rows.Err()
}

// RestartRequest is a restart a policy asks for.
type RestartRequest struct {
	DeviceID    int64
	RequestedAt time.Time
	Deadline    time.Time
}

// RestartRequests lists the pending restart requests.
func (s *Store) RestartRequests(ctx context.Context) (map[int64]RestartRequest, error) {
	rows, err := s.db.Query(ctx, `SELECT device_id, requested_at, deadline FROM restart_requests`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]RestartRequest{}
	for rows.Next() {
		var r RestartRequest
		if err := rows.Scan(&r.DeviceID, &r.RequestedAt, &r.Deadline); err != nil {
			return nil, err
		}
		out[r.DeviceID] = r
	}
	return out, rows.Err()
}

// AddRestartRequest stores a restart request (keeping an existing one).
func (s *Store) AddRestartRequest(ctx context.Context, deviceID int64, deadline time.Time) error {
	_, err := s.db.Exec(ctx, `INSERT INTO restart_requests(device_id, requested_at, deadline) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, deviceID, s.now(), deadline)
	return err
}

// DeleteRestartRequest removes a device's restart request.
func (s *Store) DeleteRestartRequest(ctx context.Context, deviceID int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM restart_requests WHERE device_id=$1`, deviceID)
	return err
}
