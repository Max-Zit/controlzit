package store

import (
	"context"
	"encoding/json"
	"time"
)

// LibScript is a saved script of the library.
type LibScript struct {
	ID          int64
	Name        string
	Description string
	Shell       string
	Body        string
	Timeout     int
	UpdatedBy   string
	UpdatedAt   time.Time
}

const libCols = `id, name, description, shell, body, timeout, updated_by, updated_at`

func scanLib(row interface{ Scan(...any) error }) (*LibScript, error) {
	var x LibScript
	if err := row.Scan(&x.ID, &x.Name, &x.Description, &x.Shell, &x.Body, &x.Timeout, &x.UpdatedBy, &x.UpdatedAt); err != nil {
		return nil, notFound(err)
	}
	return &x, nil
}

// LibScripts lists the library by name.
func (s *Store) LibScripts(ctx context.Context) ([]LibScript, error) {
	rows, err := s.db.Query(ctx, `SELECT `+libCols+` FROM scripts ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LibScript
	for rows.Next() {
		x, err := scanLib(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *x)
	}
	return out, rows.Err()
}

// LibScript loads one script.
func (s *Store) LibScript(ctx context.Context, id int64) (*LibScript, error) {
	return scanLib(s.db.QueryRow(ctx, `SELECT `+libCols+` FROM scripts WHERE id=$1`, id))
}

// SaveLibScript inserts (ID 0) or updates a script. A duplicate name is
// ErrConflict.
func (s *Store) SaveLibScript(ctx context.Context, x *LibScript) error {
	x.UpdatedAt = s.now()
	var err error
	if x.ID == 0 {
		err = s.db.QueryRow(ctx, `INSERT INTO scripts(name, description, shell, body, timeout, updated_by, updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
			x.Name, x.Description, x.Shell, x.Body, x.Timeout, x.UpdatedBy, x.UpdatedAt).Scan(&x.ID)
	} else {
		_, err = s.db.Exec(ctx, `UPDATE scripts SET name=$2, description=$3, shell=$4, body=$5, timeout=$6, updated_by=$7, updated_at=$8 WHERE id=$1`,
			x.ID, x.Name, x.Description, x.Shell, x.Body, x.Timeout, x.UpdatedBy, x.UpdatedAt)
	}
	if isUnique(err) {
		return ErrConflict
	}
	return err
}

// DeleteLibScript removes a script with its schedules (jobs keep their copy).
func (s *Store) DeleteLibScript(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM scripts WHERE id=$1`, id)
	return err
}

// ScriptTarget selects devices: all of them, or customers, sites and single
// devices (the union).
type ScriptTarget struct {
	All       bool    `json:"all,omitempty"`
	Customers []int64 `json:"customers,omitempty"`
	Sites     []int64 `json:"sites,omitempty"`
	Devices   []int64 `json:"devices,omitempty"`
}

// Empty reports whether the target selects nothing.
func (t ScriptTarget) Empty() bool {
	return !t.All && len(t.Customers) == 0 && len(t.Sites) == 0 && len(t.Devices) == 0
}

// ResolveTarget returns the IDs of the target's devices that u may see (u
// nil: all devices).
func (s *Store) ResolveTarget(ctx context.Context, u *User, t ScriptTarget) ([]int64, error) {
	if t.Customers == nil {
		t.Customers = []int64{}
	}
	if t.Sites == nil {
		t.Sites = []int64{}
	}
	if t.Devices == nil {
		t.Devices = []int64{}
	}
	rows, err := s.db.Query(ctx, `SELECT d.id`+deviceFrom+`
		WHERE ($1 OR x.customer_id = ANY($2) OR d.site_id = ANY($3) OR d.id = ANY($4))
		  AND ($5 OR x.customer_id IN (SELECT customer_id FROM user_customers WHERE user_id=$6))
		ORDER BY d.id`, t.All, t.Customers, t.Sites, t.Devices, u == nil || u.IsAdmin() || u.AllCustomers, userID(u))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ScriptJob runs a copy of a script on many devices.
type ScriptJob struct {
	ID         int64
	ScriptID   *int64
	ScheduleID *int64
	Name       string
	Shell      string
	Body       string
	Timeout    int
	CreatedBy  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	// Counts by status (lists only).
	Total, Pending, Running, Done, Failed, Expired int
}

// CreateJob stores a job with its devices (all pending).
func (s *Store) CreateJob(ctx context.Context, j *ScriptJob, devices []int64) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	j.CreatedAt = s.now()
	if err := tx.QueryRow(ctx, `INSERT INTO script_jobs(script_id, schedule_id, name, shell, body, timeout, created_by, created_at, expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`, j.ScriptID, j.ScheduleID, j.Name, j.Shell, j.Body, j.Timeout, j.CreatedBy, j.CreatedAt, j.ExpiresAt).Scan(&j.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO script_job_devices(job_id, device_id, status, updated_at) SELECT $1, unnest($2::bigint[]), 'pending', $3`, j.ID, devices, j.CreatedAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const jobCols = `j.id, j.script_id, j.schedule_id, j.name, j.shell, j.body, j.timeout, j.created_by, j.created_at, j.expires_at,
	count(d.*), count(*) FILTER (WHERE d.status='pending'), count(*) FILTER (WHERE d.status='running'),
	count(*) FILTER (WHERE d.status='done'), count(*) FILTER (WHERE d.status='failed'), count(*) FILTER (WHERE d.status='expired')`

func scanJob(row interface{ Scan(...any) error }) (*ScriptJob, error) {
	var j ScriptJob
	if err := row.Scan(&j.ID, &j.ScriptID, &j.ScheduleID, &j.Name, &j.Shell, &j.Body, &j.Timeout, &j.CreatedBy, &j.CreatedAt, &j.ExpiresAt,
		&j.Total, &j.Pending, &j.Running, &j.Done, &j.Failed, &j.Expired); err != nil {
		return nil, notFound(err)
	}
	return &j, nil
}

// Jobs lists the latest jobs; createdBy limits them to one user ("" all).
func (s *Store) Jobs(ctx context.Context, createdBy string, scriptID int64, limit int) ([]ScriptJob, error) {
	rows, err := s.db.Query(ctx, `SELECT `+jobCols+` FROM script_jobs j LEFT JOIN script_job_devices d ON d.job_id=j.id
		WHERE ($1 = '' OR j.created_by=$1) AND ($2 = 0 OR j.script_id=$2)
		GROUP BY j.id ORDER BY j.id DESC LIMIT $3`, createdBy, scriptID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScriptJob
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *j)
	}
	return out, rows.Err()
}

// Job loads one job with its counts.
func (s *Store) Job(ctx context.Context, id int64) (*ScriptJob, error) {
	return scanJob(s.db.QueryRow(ctx, `SELECT `+jobCols+` FROM script_jobs j LEFT JOIN script_job_devices d ON d.job_id=j.id WHERE j.id=$1 GROUP BY j.id`, id))
}

// JobDevice is the state of one device of a job.
type JobDevice struct {
	DeviceID   int64
	Hostname   string
	Customer   string
	CustomerID int64
	Site       string
	Status     string
	RunID      *int64
	ExitCode   *int
	TimedOut   bool
	Error      string
	UpdatedAt  time.Time
}

// JobDevices lists the devices of a job.
func (s *Store) JobDevices(ctx context.Context, jobID int64) ([]JobDevice, error) {
	rows, err := s.db.Query(ctx, `SELECT jd.device_id, d.hostname, c.name, c.id, x.name, jd.status, jd.run_id, r.exit_code, COALESCE(r.timed_out, false), COALESCE(r.error, ''), jd.updated_at
		FROM script_job_devices jd JOIN devices d ON d.id=jd.device_id JOIN sites x ON x.id=d.site_id JOIN customers c ON c.id=x.customer_id
		LEFT JOIN script_runs r ON r.id=jd.run_id
		WHERE jd.job_id=$1 ORDER BY lower(c.name), lower(d.hostname)`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JobDevice
	for rows.Next() {
		var x JobDevice
		if err := rows.Scan(&x.DeviceID, &x.Hostname, &x.Customer, &x.CustomerID, &x.Site, &x.Status, &x.RunID, &x.ExitCode, &x.TimedOut, &x.Error, &x.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// JobRun is a pending job of a device, claimed for running.
type JobRun struct {
	JobID, DeviceID int64
	Name, Shell     string
	Body            string
	Timeout         int
	CreatedBy       string
}

// ClaimJobRuns marks the next pending job of each given device as running
// (one at a time per device, at most limit runs, older jobs first) and
// returns them. Runs not claimed stay pending ("waiting").
func (s *Store) ClaimJobRuns(ctx context.Context, devices []int64, limit int) ([]JobRun, error) {
	now := s.now()
	rows, err := s.db.Query(ctx, `WITH n AS (
		SELECT DISTINCT ON (jd.device_id) jd.job_id, jd.device_id FROM script_job_devices jd JOIN script_jobs j ON j.id=jd.job_id
		WHERE jd.status='pending' AND j.expires_at > $2 AND jd.device_id = ANY($1)
		  AND NOT EXISTS (SELECT 1 FROM script_job_devices r WHERE r.device_id=jd.device_id AND r.status='running')
		ORDER BY jd.device_id, jd.job_id),
		c AS (SELECT job_id, device_id FROM n ORDER BY job_id, device_id LIMIT $3)
		UPDATE script_job_devices x SET status='running', updated_at=$2 FROM c, script_jobs j
		WHERE x.job_id=c.job_id AND x.device_id=c.device_id AND x.status='pending' AND j.id=x.job_id
		RETURNING x.job_id, x.device_id, j.name, j.shell, j.body, j.timeout, j.created_by`, devices, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JobRun
	for rows.Next() {
		var r JobRun
		if err := rows.Scan(&r.JobID, &r.DeviceID, &r.Name, &r.Shell, &r.Body, &r.Timeout, &r.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// FinishJobRun records the outcome of a claimed run.
func (s *Store) FinishJobRun(ctx context.Context, jobID, deviceID int64, status string, runID *int64) error {
	_, err := s.db.Exec(ctx, `UPDATE script_job_devices SET status=$3, run_id=$4, updated_at=$5 WHERE job_id=$1 AND device_id=$2`, jobID, deviceID, status, runID, s.now())
	return err
}

// ExpireJobs marks pending runs of expired jobs; failRunning (server start)
// also ends runs that were in flight.
func (s *Store) ExpireJobs(ctx context.Context, failRunning bool) error {
	now := s.now()
	if _, err := s.db.Exec(ctx, `UPDATE script_job_devices jd SET status='expired', updated_at=$1 FROM script_jobs j
		WHERE j.id=jd.job_id AND jd.status='pending' AND j.expires_at <= $1`, now); err != nil {
		return err
	}
	if failRunning {
		_, err := s.db.Exec(ctx, `UPDATE script_job_devices SET status='failed', updated_at=$1 WHERE status='running'`, now)
		return err
	}
	return nil
}

// ScriptSchedule runs a library script on a target at set times.
type ScriptSchedule struct {
	ID        int64
	ScriptID  int64
	Script    string // name
	Target    ScriptTarget
	Days      []int
	Minute    int // of the day, server time
	Enabled   bool
	CreatedBy string
	LastFired *time.Time
}

// Schedules lists schedules (scriptID 0: all).
func (s *Store) Schedules(ctx context.Context, scriptID int64) ([]ScriptSchedule, error) {
	rows, err := s.db.Query(ctx, `SELECT x.id, x.script_id, s.name, x.target, x.days, x.minute, x.enabled, x.created_by, x.last_fired
		FROM script_schedules x JOIN scripts s ON s.id=x.script_id WHERE ($1 = 0 OR x.script_id=$1) ORDER BY x.id`, scriptID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScriptSchedule
	for rows.Next() {
		var x ScriptSchedule
		var raw []byte
		var days []int32
		if err := rows.Scan(&x.ID, &x.ScriptID, &x.Script, &raw, &days, &x.Minute, &x.Enabled, &x.CreatedBy, &x.LastFired); err != nil {
			return nil, err
		}
		for _, d := range days {
			x.Days = append(x.Days, int(d))
		}
		_ = json.Unmarshal(raw, &x.Target)
		out = append(out, x)
	}
	return out, rows.Err()
}

// AddSchedule stores a schedule.
func (s *Store) AddSchedule(ctx context.Context, x *ScriptSchedule) error {
	raw, err := json.Marshal(x.Target)
	if err != nil {
		return err
	}
	days := make([]int32, 0, len(x.Days))
	for _, d := range x.Days {
		days = append(days, int32(d)) // #nosec G115 -- weekdays 0–6
	}
	return s.db.QueryRow(ctx, `INSERT INTO script_schedules(script_id, target, days, minute, enabled, created_by) VALUES($1,$2,$3,$4,true,$5) RETURNING id`,
		x.ScriptID, raw, days, x.Minute, x.CreatedBy).Scan(&x.ID)
}

// SetScheduleEnabled switches a schedule on or off.
func (s *Store) SetScheduleEnabled(ctx context.Context, id int64, on bool) error {
	_, err := s.db.Exec(ctx, `UPDATE script_schedules SET enabled=$2 WHERE id=$1`, id, on)
	return err
}

// DeleteSchedule removes a schedule.
func (s *Store) DeleteSchedule(ctx context.Context, id int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM script_schedules WHERE id=$1`, id)
	return err
}

// MarkScheduleFired records the time a schedule created a job; it fails
// (false) when another server process already did for the same time.
func (s *Store) MarkScheduleFired(ctx context.Context, id int64, at time.Time) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE script_schedules SET last_fired=$2 WHERE id=$1 AND (last_fired IS NULL OR last_fired < $2)`, id, at)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
