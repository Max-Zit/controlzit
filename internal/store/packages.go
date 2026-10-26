package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// SoftwarePackage is an installer of the software library.
type SoftwarePackage struct {
	ID           int64
	Name         string
	Version      string
	Description  string
	FileName     string
	Kind         string // msi, exe
	SHA256       string
	Size         int64
	Args         string
	SuccessCodes []int
	UpdatedBy    string
	UpdatedAt    time.Time
}

const pkgCols = `id, name, version, description, file_name, kind, sha256, size, args, success_codes, updated_by, updated_at`

func scanPackage(row interface{ Scan(...any) error }) (*SoftwarePackage, error) {
	var p SoftwarePackage
	if err := row.Scan(&p.ID, &p.Name, &p.Version, &p.Description, &p.FileName, &p.Kind, &p.SHA256, &p.Size, &p.Args, &p.SuccessCodes, &p.UpdatedBy, &p.UpdatedAt); err != nil {
		return nil, notFound(err)
	}
	return &p, nil
}

// SoftwarePackages lists the library by name and version.
func (s *Store) SoftwarePackages(ctx context.Context) ([]SoftwarePackage, error) {
	rows, err := s.db.Query(ctx, `SELECT `+pkgCols+` FROM software_packages ORDER BY lower(name), version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SoftwarePackage
	for rows.Next() {
		p, err := scanPackage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// SoftwarePackage loads one package.
func (s *Store) SoftwarePackage(ctx context.Context, id int64) (*SoftwarePackage, error) {
	return scanPackage(s.db.QueryRow(ctx, `SELECT `+pkgCols+` FROM software_packages WHERE id=$1`, id))
}

// SoftwarePackageFile reports whether a package of the library has the
// installer with this hash (agents may download only these).
func (s *Store) SoftwarePackageFile(ctx context.Context, sha256 string) (bool, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM software_packages WHERE sha256=$1`, sha256).Scan(&n)
	return n > 0, err
}

// SaveSoftwarePackage adds a package (ID 0) or changes its details; the
// installer of an existing package does not change.
func (s *Store) SaveSoftwarePackage(ctx context.Context, p *SoftwarePackage) error {
	p.UpdatedAt = s.now()
	var err error
	if p.ID == 0 {
		err = s.db.QueryRow(ctx, `INSERT INTO software_packages(name, version, description, file_name, kind, sha256, size, args, success_codes, updated_by, updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
			p.Name, p.Version, p.Description, p.FileName, p.Kind, p.SHA256, p.Size, p.Args, p.SuccessCodes, p.UpdatedBy, p.UpdatedAt).Scan(&p.ID)
	} else {
		var tag pgconn.CommandTag
		tag, err = s.db.Exec(ctx, `UPDATE software_packages SET name=$2, version=$3, description=$4, args=$5, success_codes=$6, updated_by=$7, updated_at=$8 WHERE id=$1`,
			p.ID, p.Name, p.Version, p.Description, p.Args, p.SuccessCodes, p.UpdatedBy, p.UpdatedAt)
		if err == nil && tag.RowsAffected() == 0 {
			err = ErrNotFound
		}
	}
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// DeleteSoftwarePackage removes a package; it reports whether another
// package still uses the same installer file.
func (s *Store) DeleteSoftwarePackage(ctx context.Context, id int64) (shared bool, err error) {
	var sha string
	if err := s.db.QueryRow(ctx, `DELETE FROM software_packages WHERE id=$1 RETURNING sha256`, id).Scan(&sha); err != nil {
		return false, notFound(err)
	}
	return s.SoftwarePackageFile(ctx, sha)
}
