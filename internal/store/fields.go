package store

import (
	"context"
	"errors"
	"strings"
)

// CustomField is a field administrators defined for devices or customers.
type CustomField struct {
	ID    int64
	Scope string // device, customer
	Name  string
	Kind  string // text, number, date
	Value string // on pages: the value of one device or customer
}

// fieldTable is where the values of a scope are.
func fieldTable(scope string) (table, column string, err error) {
	switch scope {
	case "device":
		return "device_field_values", "device_id", nil
	case "customer":
		return "customer_field_values", "customer_id", nil
	}
	return "", "", errors.New("unknown field scope")
}

// CustomFields lists the fields of a scope.
func (s *Store) CustomFields(ctx context.Context, scope string) ([]CustomField, error) {
	rows, err := s.db.Query(ctx, `SELECT id, scope, name, kind FROM custom_fields WHERE scope=$1 ORDER BY lower(name)`, scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CustomField
	for rows.Next() {
		var f CustomField
		if err := rows.Scan(&f.ID, &f.Scope, &f.Name, &f.Kind); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// AddCustomField defines a field (ErrConflict: the name exists).
func (s *Store) AddCustomField(ctx context.Context, scope, name, kind string) (int64, error) {
	name, err := checkText(strings.TrimSpace(name), 60)
	if err != nil || name == "" {
		return 0, errors.New("a field needs a name of up to 60 characters")
	}
	var id int64
	err = s.db.QueryRow(ctx, `INSERT INTO custom_fields(scope, name, kind, created_at) VALUES($1,$2,$3,$4) RETURNING id`, scope, name, kind, s.now()).Scan(&id)
	if isUnique(err) {
		return 0, ErrConflict
	}
	return id, err
}

// DeleteCustomField removes a field and its values.
func (s *Store) DeleteCustomField(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM custom_fields WHERE id=$1`, id)
	return err
}

// FieldValues returns the fields of a scope with the values of one target.
func (s *Store) FieldValues(ctx context.Context, scope string, targetID int64) ([]CustomField, error) {
	table, col, err := fieldTable(scope)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT f.id, f.scope, f.name, f.kind, COALESCE(v.value, '') FROM custom_fields f
		LEFT JOIN `+table+` v ON v.field_id=f.id AND v.`+col+`=$2 WHERE f.scope=$1 ORDER BY lower(f.name)`, scope, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CustomField
	for rows.Next() {
		var f CustomField
		if err := rows.Scan(&f.ID, &f.Scope, &f.Name, &f.Kind, &f.Value); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// SetFieldValues stores values of a target by field ID; an empty value
// removes it.
func (s *Store) SetFieldValues(ctx context.Context, scope string, targetID int64, values map[int64]string) error {
	table, col, err := fieldTable(scope)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for fid, v := range values {
		if v == "" {
			_, err = tx.Exec(ctx, `DELETE FROM `+table+` WHERE field_id=$1 AND `+col+`=$2`, fid, targetID)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO `+table+`(field_id, `+col+`, value) SELECT $1, $2, $3 FROM custom_fields WHERE id=$1 AND scope=$4
				ON CONFLICT (field_id, `+col+`) DO UPDATE SET value=EXCLUDED.value`, fid, targetID, v, scope)
		}
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// AllFieldValues returns every value of a scope by target and field name.
func (s *Store) AllFieldValues(ctx context.Context, scope string) (map[int64]map[string]string, error) {
	table, col, err := fieldTable(scope)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT v.`+col+`, f.name, v.value FROM `+table+` v JOIN custom_fields f ON f.id=v.field_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]map[string]string{}
	for rows.Next() {
		var id int64
		var name, value string
		if err := rows.Scan(&id, &name, &value); err != nil {
			return nil, err
		}
		if out[id] == nil {
			out[id] = map[string]string{}
		}
		out[id][name] = value
	}
	return out, rows.Err()
}
