package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/max-zit/rmmzit/internal/auth"
	"github.com/max-zit/rmmzit/internal/proto"
)

// Device is a managed machine.
type Device struct {
	ID           int64
	SiteID       int64
	Site         string
	CustomerID   int64
	Customer     string
	AgentID      string
	Hostname     string
	OS           string
	OSVersion    string
	OSBuild      string
	AgentVersion string
	LastUser     string
	BootTime     *time.Time
	RemoteIP     string
	EnrolledAt   time.Time
	LastSeenAt   *time.Time
	Connected    bool
	InventoryAt  *time.Time
	Inventory    *proto.Inventory
}

// Online reports a device seen within the window.
func (d *Device) Online(now time.Time, window time.Duration) bool {
	return d.Connected && d.LastSeenAt != nil && now.Sub(*d.LastSeenAt) < window
}

func clip(s string, n int) string {
	s = strings.ToValidUTF8(strings.TrimSpace(s), "?")
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// EnrollDevice consumes one use of an enrollment token and registers the
// agent key in the token's site, in one transaction.
func (s *Store) EnrollDevice(ctx context.Context, token string, pub []byte, hostname, osName, agentVersion, ip string) (*Device, error) {
	defer s.scopesChanged()
	if len(pub) != 32 {
		return nil, errors.New("bad agent key")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var siteID, tokenID int64
	err = tx.QueryRow(ctx, `UPDATE enrollment_tokens SET uses=uses+1
		WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at > $2 AND uses < max_uses RETURNING site_id, id`,
		auth.HashToken("enroll", token), s.now()).Scan(&siteID, &tokenID)
	if err != nil {
		return nil, ErrTokenInvalid
	}
	var id int64
	err = tx.QueryRow(ctx, `INSERT INTO devices(site_id, agent_id, hostname, os, key_id, public_key, token_id, agent_version, remote_ip, enrolled_at)
		VALUES($1, gen_random_uuid(), $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
		siteID, clip(hostname, 255), clip(osName, 200), proto.KeyID(pub), pub, tokenID, clip(agentVersion, 40), ip, s.now()).Scan(&id)
	if isUnique(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.Device(ctx, id)
}

const deviceCols = `d.id, d.site_id, x.name, x.customer_id, c.name, d.agent_id::text, d.hostname, d.os, d.os_version, d.os_build,
	d.agent_version, d.last_user, d.boot_time, d.remote_ip, d.enrolled_at, d.last_seen_at, d.connected, d.inventory_at`

const deviceFrom = ` FROM devices d JOIN sites x ON x.id=d.site_id JOIN customers c ON c.id=x.customer_id `

func scanDevice(row interface{ Scan(...any) error }, extra ...any) (*Device, error) {
	d := &Device{}
	dst := []any{&d.ID, &d.SiteID, &d.Site, &d.CustomerID, &d.Customer, &d.AgentID, &d.Hostname, &d.OS, &d.OSVersion, &d.OSBuild,
		&d.AgentVersion, &d.LastUser, &d.BootTime, &d.RemoteIP, &d.EnrolledAt, &d.LastSeenAt, &d.Connected, &d.InventoryAt}
	return d, row.Scan(append(dst, extra...)...)
}

// Device loads a device with its inventory.
func (s *Store) Device(ctx context.Context, id int64) (*Device, error) {
	var raw []byte
	d, err := scanDevice(s.db.QueryRow(ctx, `SELECT `+deviceCols+`, d.inventory`+deviceFrom+`WHERE d.id=$1`, id), &raw)
	if err != nil {
		return nil, notFound(err)
	}
	if raw != nil {
		d.Inventory = &proto.Inventory{}
		if err := json.Unmarshal(raw, d.Inventory); err != nil {
			d.Inventory = nil
		}
	}
	return d, nil
}

// DeviceByKey finds the device of an agent key.
func (s *Store) DeviceByKey(ctx context.Context, pub []byte) (*Device, error) {
	d, err := scanDevice(s.db.QueryRow(ctx, `SELECT `+deviceCols+deviceFrom+`WHERE d.key_id=$1`, proto.KeyID(pub)))
	return d, notFound(err)
}

// DeviceFilter selects devices.
type DeviceFilter struct {
	SiteID     int64
	CustomerID int64
	Query      string
	Limit      int
}

// Devices lists the devices the user may see.
func (s *Store) Devices(ctx context.Context, u *User, f DeviceFilter) ([]*Device, error) {
	if f.Limit <= 0 || f.Limit > 2000 {
		f.Limit = 500
	}
	q := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(f.Query) + "%"
	rows, err := s.db.Query(ctx, `SELECT `+deviceCols+deviceFrom+`
		WHERE ($1 OR x.customer_id IN (SELECT customer_id FROM user_customers WHERE user_id=$2))
		  AND ($3 = 0 OR d.site_id=$3) AND ($4 = 0 OR x.customer_id=$4)
		  AND ($5 = '%%' OR d.hostname ILIKE $5 OR d.last_user ILIKE $5 OR d.os ILIKE $5 OR c.name ILIKE $5)
		ORDER BY lower(c.name), lower(x.name), lower(d.hostname) LIMIT $6`,
		u.IsAdmin() || u.AllCustomers, u.ID, f.SiteID, f.CustomerID, q, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AgentSeen records a hello or heartbeat; connected marks the channel state.
func (s *Store) AgentSeen(ctx context.Context, id int64, h *proto.Hello, ip string) error {
	var boot *time.Time
	if h != nil && !h.BootTime.IsZero() {
		b := h.BootTime
		boot = &b
	}
	if h == nil {
		_, err := s.db.Exec(ctx, `UPDATE devices SET last_seen_at=$2, connected=true WHERE id=$1`, id, s.now())
		return err
	}
	_, err := s.db.Exec(ctx, `UPDATE devices SET last_seen_at=$2, connected=true, remote_ip=$3, hostname=CASE WHEN $4<>'' THEN $4 ELSE hostname END,
		os=CASE WHEN $5<>'' THEN $5 ELSE os END, os_version=$6, os_build=$7, agent_version=$8, last_user=$9, boot_time=COALESCE($10, boot_time) WHERE id=$1`,
		id, s.now(), ip, clip(h.Hostname, 255), clip(h.OS, 200), clip(h.OSVersion, 60), clip(h.OSBuild, 60), clip(h.AgentVersion, 40), clip(h.LoggedOnUser, 200), boot)
	return err
}

// AgentHeartbeat records a heartbeat.
func (s *Store) AgentHeartbeat(ctx context.Context, id int64, hb proto.Heartbeat) error {
	var boot *time.Time
	if !hb.BootTime.IsZero() {
		boot = &hb.BootTime
	}
	_, err := s.db.Exec(ctx, `UPDATE devices SET last_seen_at=$2, connected=true, last_user=$3, boot_time=COALESCE($4, boot_time) WHERE id=$1`,
		id, s.now(), clip(hb.LoggedOnUser, 200), boot)
	return err
}

// AgentDisconnected marks the channel closed.
func (s *Store) AgentDisconnected(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `UPDATE devices SET connected=false WHERE id=$1`, id)
	return err
}

// ResetConnected marks all agents disconnected (server start).
func (s *Store) ResetConnected(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `UPDATE devices SET connected=false WHERE connected`)
	return err
}

// SaveInventory stores the latest inventory of a device.
func (s *Store) SaveInventory(ctx context.Context, id int64, inv *proto.Inventory) error {
	raw, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	osName := clip(inv.OS.Name, 200)
	_, err = s.db.Exec(ctx, `UPDATE devices SET inventory=$2, inventory_at=$3, os=CASE WHEN $4<>'' THEN $4 ELSE os END,
		os_version=CASE WHEN $5<>'' THEN $5 ELSE os_version END, os_build=CASE WHEN $6<>'' THEN $6 ELSE os_build END WHERE id=$1`,
		id, raw, s.now(), osName, clip(inv.OS.Version, 60), clip(inv.OS.Build, 60))
	return err
}

// DeleteDevice removes a device; its agent can no longer connect.
func (s *Store) DeleteDevice(ctx context.Context, id int64) error {
	defer s.scopesChanged()
	tag, err := s.db.Exec(ctx, `DELETE FROM devices WHERE id=$1`, id)
	if err == nil {
		_, err = s.db.Exec(ctx, `DELETE FROM policy_assignments WHERE target_type='device' AND target_id=$1`, id)
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// IsWindows reports whether the device runs Windows (unknown counts as
// Windows: every agent before the Linux one).
func (d *Device) IsWindows() bool {
	return d.OS == "" || strings.Contains(d.OS, "Windows")
}
