package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
)

// SavePatchReport stores the Windows Update report of a device and returns
// the previous one (nil if there was none).
func (s *Store) SavePatchReport(ctx context.Context, deviceID int64, r *proto.PatchReport) (*proto.PatchReport, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	var prevRaw []byte
	err = s.db.QueryRow(ctx, `WITH old AS (SELECT report FROM device_patches WHERE device_id=$1)
		INSERT INTO device_patches(device_id, report, updated_at) VALUES($1,$2,$3)
		ON CONFLICT (device_id) DO UPDATE SET report=EXCLUDED.report, updated_at=EXCLUDED.updated_at
		RETURNING (SELECT report FROM old)`, deviceID, raw, s.now()).Scan(&prevRaw)
	if err != nil || prevRaw == nil {
		return nil, err
	}
	var prev proto.PatchReport
	if json.Unmarshal(prevRaw, &prev) != nil {
		return nil, nil
	}
	return &prev, nil
}

// PatchReport loads the Windows Update report of a device (nil if none).
func (s *Store) PatchReport(ctx context.Context, deviceID int64) (*proto.PatchReport, time.Time, error) {
	var raw []byte
	var at time.Time
	err := s.db.QueryRow(ctx, `SELECT report, updated_at FROM device_patches WHERE device_id=$1`, deviceID).Scan(&raw, &at)
	if err != nil {
		if notFound(err) == ErrNotFound {
			return nil, at, nil
		}
		return nil, at, err
	}
	var r proto.PatchReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, at, err
	}
	return &r, at, nil
}

// DevicePatches is a device with its Windows Update report.
type DevicePatches struct {
	*Device
	Report        *proto.PatchReport
	AutoInstallOn *time.Time
}

// PatchOverview lists the devices the user may see with their reports.
func (s *Store) PatchOverview(ctx context.Context, u *User) ([]DevicePatches, error) {
	rows, err := s.db.Query(ctx, `SELECT `+deviceCols+`, p.report, p.auto_install_on`+deviceFrom+`
		LEFT JOIN device_patches p ON p.device_id=d.id
		WHERE ($1 OR x.customer_id IN (SELECT customer_id FROM user_customers WHERE user_id=$2))
		ORDER BY lower(c.name), lower(x.name), lower(d.hostname) LIMIT 2000`, u == nil || u.IsAdmin() || u.AllCustomers, userID(u))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DevicePatches
	for rows.Next() {
		var raw []byte
		var dp DevicePatches
		d, err := scanDevice(rows, &raw, &dp.AutoInstallOn)
		if err != nil {
			return nil, err
		}
		dp.Device = d
		if raw != nil {
			var r proto.PatchReport
			if json.Unmarshal(raw, &r) == nil {
				dp.Report = &r
			}
		}
		out = append(out, dp)
	}
	return out, rows.Err()
}

// MarkAutoInstall records that the automatic installation ran today.
func (s *Store) MarkAutoInstall(ctx context.Context, deviceID int64, day time.Time) error {
	_, err := s.db.Exec(ctx, `UPDATE device_patches SET auto_install_on=$2 WHERE device_id=$1`, deviceID, day.Format("2006-01-02"))
	return err
}

func userID(u *User) int64 {
	if u == nil {
		return 0
	}
	return u.ID
}
