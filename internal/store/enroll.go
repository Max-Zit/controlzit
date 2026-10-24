package store

import (
	"context"
	"errors"
	"time"

	"github.com/max-zit/controlzit/internal/auth"
)

// EnrollToken lets agent installers join devices to a site. Only its
// hash is stored; the token is shown once when it is created.
type EnrollToken struct {
	ID        int64
	SiteID    int64
	Label     string
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
	MaxUses   int
	Uses      int
	RevokedAt *time.Time
}

// Active reports whether the token can still be used.
func (t *EnrollToken) Active(now time.Time) bool {
	return t.RevokedAt == nil && now.Before(t.ExpiresAt) && t.Uses < t.MaxUses
}

// EnrollTokenPrefix marks enrollment tokens so they are recognizable in
// installer command lines and secret scanners.
const EnrollTokenPrefix = "czet_"

// CreateEnrollToken makes a token for a site and returns its value.
func (s *Store) CreateEnrollToken(ctx context.Context, siteID int64, label, by string, valid time.Duration, maxUses int) (string, error) {
	label, err := checkText(label, 120)
	if err != nil {
		return "", err
	}
	if valid < time.Hour || valid > 366*24*time.Hour {
		return "", errors.New("a token must be valid between 1 hour and 1 year")
	}
	if maxUses < 1 || maxUses > 100000 {
		return "", errors.New("uses must be between 1 and 100000")
	}
	tok := EnrollTokenPrefix + auth.RandomToken(32)
	_, err = s.db.Exec(ctx, `INSERT INTO enrollment_tokens(site_id, token_hash, label, created_by, created_at, expires_at, max_uses) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		siteID, auth.HashToken("enroll", tok), label, by, s.now(), s.now().Add(valid), maxUses)
	if isFK(err) {
		return "", ErrNotFound
	}
	return tok, err
}

// EnrollTokens lists the tokens of a site, newest first.
func (s *Store) EnrollTokens(ctx context.Context, siteID int64) ([]EnrollToken, error) {
	rows, err := s.db.Query(ctx, `SELECT id, site_id, label, created_by, created_at, expires_at, max_uses, uses, revoked_at FROM enrollment_tokens WHERE site_id=$1 ORDER BY id DESC`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollToken
	for rows.Next() {
		var t EnrollToken
		if err := rows.Scan(&t.ID, &t.SiteID, &t.Label, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.MaxUses, &t.Uses, &t.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeEnrollToken stops a token of a site.
func (s *Store) RevokeEnrollToken(ctx context.Context, siteID, id int64) error {
	tag, err := s.db.Exec(ctx, `UPDATE enrollment_tokens SET revoked_at=$3 WHERE id=$1 AND site_id=$2 AND revoked_at IS NULL`, id, siteID, s.now())
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ErrTokenInvalid is returned for unknown, expired, used up or revoked tokens.
var ErrTokenInvalid = errors.New("enrollment code is invalid, expired or used up")

// UseEnrollToken consumes one use of a token and returns its site. It is
// atomic, so a single-use token cannot enroll two devices.
func (s *Store) UseEnrollToken(ctx context.Context, tok string) (siteID int64, err error) {
	err = s.db.QueryRow(ctx, `UPDATE enrollment_tokens SET uses=uses+1
		WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at > $2 AND uses < max_uses RETURNING site_id`,
		auth.HashToken("enroll", tok), s.now()).Scan(&siteID)
	if err != nil {
		return 0, ErrTokenInvalid
	}
	return siteID, nil
}
