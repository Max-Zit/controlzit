package store

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// Customer is a company whose machines are managed.
type Customer struct {
	ID        int64
	Name      string
	Notes     string
	CreatedAt time.Time
	Sites     int
	Devices   int
}

// Site is a location of a customer (office, branch, data center).
type Site struct {
	ID         int64
	CustomerID int64
	Customer   string
	Name       string
	Address    string
	Notes      string
	CreatedAt  time.Time
	Devices    int
}

func checkName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 120 {
		return "", errors.New("the name must be 1–120 characters")
	}
	return name, nil
}

func checkText(s string, limit int) (string, error) {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > limit {
		return "", errors.New("the text is too long")
	}
	return s, nil
}

// Customers lists the customers user may see.
func (s *Store) Customers(ctx context.Context, u *User) ([]Customer, error) {
	rows, err := s.db.Query(ctx, `SELECT c.id, c.name, c.notes, c.created_at,
		(SELECT count(*) FROM sites WHERE customer_id=c.id),
		(SELECT count(*) FROM devices d JOIN sites x ON x.id=d.site_id WHERE x.customer_id=c.id)
		FROM customers c
		WHERE $1 OR c.id IN (SELECT customer_id FROM user_customers WHERE user_id=$2)
		ORDER BY lower(c.name)`, u == nil || u.IsAdmin() || u.AllCustomers, userID(u))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Customer
	for rows.Next() {
		var c Customer
		if err := rows.Scan(&c.ID, &c.Name, &c.Notes, &c.CreatedAt, &c.Sites, &c.Devices); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AllCustomers lists every customer (for the user editor).
func (s *Store) AllCustomers(ctx context.Context) ([]Customer, error) {
	return s.Customers(ctx, &User{Role: RoleAdmin})
}

// Customer loads one customer.
func (s *Store) Customer(ctx context.Context, id int64) (*Customer, error) {
	c := &Customer{}
	err := s.db.QueryRow(ctx, `SELECT id, name, notes, created_at FROM customers WHERE id=$1`, id).Scan(&c.ID, &c.Name, &c.Notes, &c.CreatedAt)
	return c, notFound(err)
}

// CreateCustomer adds a customer.
func (s *Store) CreateCustomer(ctx context.Context, name, notes string) (int64, error) {
	name, err := checkName(name)
	if err != nil {
		return 0, err
	}
	if notes, err = checkText(notes, 4000); err != nil {
		return 0, err
	}
	var id int64
	err = s.db.QueryRow(ctx, `INSERT INTO customers(name, notes) VALUES($1,$2) RETURNING id`, name, notes).Scan(&id)
	if isUnique(err) {
		return 0, ErrConflict
	}
	return id, err
}

// UpdateCustomer renames a customer or changes its notes.
func (s *Store) UpdateCustomer(ctx context.Context, id int64, name, notes string) error {
	name, err := checkName(name)
	if err != nil {
		return err
	}
	if notes, err = checkText(notes, 4000); err != nil {
		return err
	}
	tag, err := s.db.Exec(ctx, `UPDATE customers SET name=$2, notes=$3 WHERE id=$1`, id, name, notes)
	if isUnique(err) {
		return ErrConflict
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ErrInUse is returned when deleting something that still has children.
var ErrInUse = errors.New("still in use")

// DeleteCustomer removes a customer without sites.
func (s *Store) DeleteCustomer(ctx context.Context, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM customers WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 1 {
		_, err = s.db.Exec(ctx, `DELETE FROM policy_assignments WHERE target_type='customer' AND target_id=$1`, id)
	}
	if isFK(err) {
		return ErrInUse
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

const siteCols = `s.id, s.customer_id, c.name, s.name, s.address, s.notes, s.created_at, (SELECT count(*) FROM devices WHERE site_id=s.id)`

func scanSite(row interface{ Scan(...any) error }) (Site, error) {
	var x Site
	err := row.Scan(&x.ID, &x.CustomerID, &x.Customer, &x.Name, &x.Address, &x.Notes, &x.CreatedAt, &x.Devices)
	return x, err
}

// Sites lists the sites of a customer.
func (s *Store) Sites(ctx context.Context, customerID int64) ([]Site, error) {
	rows, err := s.db.Query(ctx, `SELECT `+siteCols+` FROM sites s JOIN customers c ON c.id=s.customer_id WHERE s.customer_id=$1 ORDER BY lower(s.name)`, customerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Site
	for rows.Next() {
		x, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// Site loads one site.
func (s *Store) Site(ctx context.Context, id int64) (*Site, error) {
	x, err := scanSite(s.db.QueryRow(ctx, `SELECT `+siteCols+` FROM sites s JOIN customers c ON c.id=s.customer_id WHERE s.id=$1`, id))
	if err != nil {
		return nil, notFound(err)
	}
	return &x, nil
}

// CreateSite adds a site to a customer.
func (s *Store) CreateSite(ctx context.Context, customerID int64, name, address, notes string) (int64, error) {
	name, err := checkName(name)
	if err != nil {
		return 0, err
	}
	if address, err = checkText(address, 300); err != nil {
		return 0, err
	}
	if notes, err = checkText(notes, 4000); err != nil {
		return 0, err
	}
	var id int64
	err = s.db.QueryRow(ctx, `INSERT INTO sites(customer_id, name, address, notes) VALUES($1,$2,$3,$4) RETURNING id`, customerID, name, address, notes).Scan(&id)
	switch {
	case isUnique(err):
		return 0, ErrConflict
	case isFK(err):
		return 0, ErrNotFound
	}
	return id, err
}

// UpdateSite changes a site.
func (s *Store) UpdateSite(ctx context.Context, id int64, name, address, notes string) error {
	name, err := checkName(name)
	if err != nil {
		return err
	}
	if address, err = checkText(address, 300); err != nil {
		return err
	}
	if notes, err = checkText(notes, 4000); err != nil {
		return err
	}
	tag, err := s.db.Exec(ctx, `UPDATE sites SET name=$2, address=$3, notes=$4 WHERE id=$1`, id, name, address, notes)
	if isUnique(err) {
		return ErrConflict
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// DeleteSite removes a site without devices; its enrollment tokens go with it.
func (s *Store) DeleteSite(ctx context.Context, id int64) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM policy_assignments WHERE target_type='site' AND target_id=$1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM enrollment_tokens WHERE site_id=$1`, id); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM sites WHERE id=$1`, id)
	if isFK(err) {
		return ErrInUse
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

// Counts are the numbers on the overview.
type Counts struct{ Customers, Sites, Devices, Online int }

// Overview counts what the user may see.
func (s *Store) Overview(ctx context.Context, u *User, onlineSince time.Time) (Counts, error) {
	var c Counts
	all := u.IsAdmin() || u.AllCustomers
	err := s.db.QueryRow(ctx, `WITH vis AS (SELECT id FROM customers WHERE $1 OR id IN (SELECT customer_id FROM user_customers WHERE user_id=$2))
		SELECT (SELECT count(*) FROM vis),
		       (SELECT count(*) FROM sites WHERE customer_id IN (SELECT id FROM vis)),
		       (SELECT count(*) FROM devices d JOIN sites x ON x.id=d.site_id WHERE x.customer_id IN (SELECT id FROM vis)),
		       (SELECT count(*) FROM devices d JOIN sites x ON x.id=d.site_id WHERE x.customer_id IN (SELECT id FROM vis) AND d.connected AND d.last_seen_at > $3)`,
		all, u.ID, onlineSince).Scan(&c.Customers, &c.Sites, &c.Devices, &c.Online)
	return c, err
}
