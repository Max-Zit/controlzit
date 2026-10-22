package store

import (
	"context"
	"strings"
	"time"
)

// ScriptRun is a script run on a device from the console.
type ScriptRun struct {
	ID        int64
	DeviceID  int64
	Username  string
	Shell     string
	Script    string
	StartedAt time.Time
	Duration  time.Duration
	ExitCode  *int
	TimedOut  bool
	Truncated bool
	Output    string
	Error     string
	JobID     *int64
}

// AddScriptRun stores a finished run and sets its ID.
func (s *Store) AddScriptRun(ctx context.Context, r *ScriptRun) error {
	return s.db.QueryRow(ctx, `INSERT INTO script_runs(device_id, username, shell, script, started_at, duration_ms, exit_code, timed_out, truncated, output, error, job_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
		r.DeviceID, r.Username, r.Shell, r.Script, r.StartedAt, r.Duration.Milliseconds(), r.ExitCode, r.TimedOut, r.Truncated,
		strings.ToValidUTF8(strings.ReplaceAll(r.Output, "\x00", ""), "?"), r.Error, r.JobID).Scan(&r.ID)
}

const scriptCols = `id, device_id, username, shell, script, started_at, duration_ms, exit_code, timed_out, truncated, output, error`

func scanScriptRun(row interface{ Scan(...any) error }) (*ScriptRun, error) {
	var r ScriptRun
	var ms int64
	if err := row.Scan(&r.ID, &r.DeviceID, &r.Username, &r.Shell, &r.Script, &r.StartedAt, &ms, &r.ExitCode, &r.TimedOut, &r.Truncated, &r.Output, &r.Error); err != nil {
		return nil, notFound(err)
	}
	r.Duration = time.Duration(ms) * time.Millisecond
	return &r, nil
}

// ScriptRun loads one run of a device.
func (s *Store) ScriptRun(ctx context.Context, deviceID, id int64) (*ScriptRun, error) {
	return scanScriptRun(s.db.QueryRow(ctx, `SELECT `+scriptCols+` FROM script_runs WHERE device_id=$1 AND id=$2`, deviceID, id))
}

// ScriptRuns lists the latest runs of a device (without the output).
func (s *Store) ScriptRuns(ctx context.Context, deviceID int64, limit int) ([]ScriptRun, error) {
	rows, err := s.db.Query(ctx, `SELECT id, device_id, username, shell, left(script, 200), started_at, duration_ms, exit_code, timed_out, truncated, '', error
		FROM script_runs WHERE device_id=$1 ORDER BY id DESC LIMIT $2`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScriptRun
	for rows.Next() {
		r, err := scanScriptRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}
