package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/auth"
)

// TokenPrefix starts every API token.
const TokenPrefix = "czt_"

// APIToken is a personal API token (the secret is shown only once).
type APIToken struct {
	ID         int64
	UserID     int64
	Name       string
	Role       string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
}

var roleRank = map[string]int{RoleReadOnly: 1, RoleTechnician: 2, RoleAdmin: 3}

// CreateAPIToken makes a token for a user; days 0 means it never expires.
func (s *Store) CreateAPIToken(ctx context.Context, u *User, name, role string, days int) (string, *APIToken, error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "" || len(name) > 100:
		return "", nil, errors.New("name the token (for example the tool that uses it)")
	case !ValidRole(role):
		return "", nil, errors.New("choose a role")
	case roleRank[role] > roleRank[u.Role]:
		return "", nil, errors.New("a token cannot have more rights than your own role")
	case days < 0 || days > 3650:
		return "", nil, errors.New("the validity must be 0 (no end) to 3650 days")
	}
	t := &APIToken{UserID: u.ID, Name: name, Role: role, CreatedAt: s.now()}
	if days > 0 {
		e := t.CreatedAt.AddDate(0, 0, days)
		t.ExpiresAt = &e
	}
	secret := TokenPrefix + auth.RandomToken(32)
	err := s.db.QueryRow(ctx, `INSERT INTO api_tokens(user_id, name, role, token_hash, created_at, expires_at) VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,
		t.UserID, t.Name, t.Role, auth.HashToken("api", secret), t.CreatedAt, t.ExpiresAt).Scan(&t.ID)
	return secret, t, err
}

// APITokens lists the tokens of a user.
func (s *Store) APITokens(ctx context.Context, userID int64) ([]APIToken, error) {
	rows, err := s.db.Query(ctx, `SELECT id, user_id, name, role, created_at, expires_at, last_used_at FROM api_tokens WHERE user_id=$1 ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.Role, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteAPIToken removes a token of a user.
func (s *Store) DeleteAPIToken(ctx context.Context, userID, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM api_tokens WHERE id=$1 AND user_id=$2`, id, userID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// TokenUser authenticates a token: the user it acts as, with the token's
// role if that is lower than the user's, and the token.
func (s *Store) TokenUser(ctx context.Context, secret string) (*User, *APIToken, error) {
	if !strings.HasPrefix(secret, TokenPrefix) || len(secret) > 200 {
		return nil, nil, ErrNotFound
	}
	var t APIToken
	err := s.db.QueryRow(ctx, `UPDATE api_tokens SET last_used_at=$2 WHERE token_hash=$1 AND (expires_at IS NULL OR expires_at > $2)
		RETURNING id, user_id, name, role, created_at, expires_at, last_used_at`, auth.HashToken("api", secret), s.now()).
		Scan(&t.ID, &t.UserID, &t.Name, &t.Role, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt)
	if err != nil {
		return nil, nil, notFound(err)
	}
	u, err := s.UserByID(ctx, t.UserID)
	if err != nil || u.Disabled {
		return nil, nil, ErrNotFound
	}
	if roleRank[t.Role] < roleRank[u.Role] {
		// An administrator's token with a lower role still sees every customer.
		if u.IsAdmin() {
			u.AllCustomers = true
		}
		u.Role = t.Role
	}
	return u, &t, nil
}
