package store

import (
	"context"
	"time"
)

// RecoveryKey is a stored BitLocker recovery key (sealed).
type RecoveryKey struct {
	DeviceID    int64
	ProtectorID string
	Volume      string
	Sealed      string
	FirstSeen   time.Time
	LastSeen    time.Time
}

// SaveRecoveryKey stores or refreshes a recovery key.
func (s *Store) SaveRecoveryKey(ctx context.Context, deviceID int64, protectorID, volume, sealed string) (added bool, err error) {
	now := s.now()
	var inserted bool
	err = s.db.QueryRow(ctx, `INSERT INTO device_recovery_keys(device_id, protector_id, volume, sealed, first_seen, last_seen) VALUES($1,$2,$3,$4,$5,$5)
		ON CONFLICT (device_id, protector_id) DO UPDATE SET volume=EXCLUDED.volume, sealed=EXCLUDED.sealed, last_seen=EXCLUDED.last_seen
		RETURNING (xmax = 0)`, deviceID, protectorID, volume, sealed, now).Scan(&inserted)
	return inserted, err
}

// RecoveryKeys lists the keys of a device, newest first.
func (s *Store) RecoveryKeys(ctx context.Context, deviceID int64) ([]RecoveryKey, error) {
	rows, err := s.db.Query(ctx, `SELECT device_id, protector_id, volume, sealed, first_seen, last_seen FROM device_recovery_keys
		WHERE device_id=$1 ORDER BY volume, last_seen DESC`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RecoveryKey
	for rows.Next() {
		var k RecoveryKey
		if err := rows.Scan(&k.DeviceID, &k.ProtectorID, &k.Volume, &k.Sealed, &k.FirstSeen, &k.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RecoveryKey loads one key of a device.
func (s *Store) RecoveryKey(ctx context.Context, deviceID int64, protectorID string) (*RecoveryKey, error) {
	var k RecoveryKey
	err := s.db.QueryRow(ctx, `SELECT device_id, protector_id, volume, sealed, first_seen, last_seen FROM device_recovery_keys WHERE device_id=$1 AND protector_id=$2`,
		deviceID, protectorID).Scan(&k.DeviceID, &k.ProtectorID, &k.Volume, &k.Sealed, &k.FirstSeen, &k.LastSeen)
	if err != nil {
		return nil, notFound(err)
	}
	return &k, nil
}
