package store

import (
	"context"
	"encoding/json"
	"time"
)

// DeviceTask is one action of the console on a device (a script, an
// installation, a Windows Update search …): queued until the device is
// online, then running, then finished.
type DeviceTask struct {
	ID         int64
	DeviceID   int64
	Kind       string
	Title      string // a translation key; TitleArgs fill its %s
	TitleArgs  []string
	Args       json.RawMessage
	Status     string // queued, running, done, failed, cancelled, expired
	CreatedBy  string
	CreatedAt  time.Time
	StartedAt  *time.Time
	FinishedAt *time.Time
	ExpiresAt  time.Time
	Result     string // a translation key; ResultArgs fill its %s
	ResultArgs []string
	Link       string
	JobID      *int64
}

// Active reports whether the task is still queued or running.
func (t *DeviceTask) Active() bool { return t.Status == "queued" || t.Status == "running" }

const taskCols = `id, device_id, kind, title, title_args, args, status, created_by, created_at, started_at, finished_at, expires_at, result, result_args, link, job_id`

func scanTask(row interface{ Scan(...any) error }) (*DeviceTask, error) {
	var t DeviceTask
	if err := row.Scan(&t.ID, &t.DeviceID, &t.Kind, &t.Title, &t.TitleArgs, &t.Args, &t.Status, &t.CreatedBy, &t.CreatedAt, &t.StartedAt, &t.FinishedAt,
		&t.ExpiresAt, &t.Result, &t.ResultArgs, &t.Link, &t.JobID); err != nil {
		return nil, notFound(err)
	}
	return &t, nil
}

func (s *Store) tasks(ctx context.Context, q string, args ...any) ([]DeviceTask, error) {
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceTask
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// AddTask queues a task.
func (s *Store) AddTask(ctx context.Context, t *DeviceTask) error {
	t.Status, t.CreatedAt = "queued", s.now()
	if len(t.Args) == 0 {
		t.Args = json.RawMessage("{}")
	}
	return s.db.QueryRow(ctx, `INSERT INTO device_tasks(device_id, kind, title, title_args, args, status, created_by, created_at, expires_at)
		VALUES($1,$2,$3,$9,$4,$5,$6,$7,$8) RETURNING id`, t.DeviceID, t.Kind, t.Title, t.Args, t.Status, t.CreatedBy, t.CreatedAt, t.ExpiresAt, nonNil(t.TitleArgs)).Scan(&t.ID)
}

// AddRunningTask records a task that starts at once (a job run).
func (s *Store) AddRunningTask(ctx context.Context, t *DeviceTask) error {
	now := s.now()
	t.Status, t.CreatedAt, t.StartedAt, t.ExpiresAt = "running", now, &now, now
	if len(t.Args) == 0 {
		t.Args = json.RawMessage("{}")
	}
	return s.db.QueryRow(ctx, `INSERT INTO device_tasks(device_id, kind, title, title_args, args, status, created_by, created_at, started_at, expires_at, job_id)
		VALUES($1,$2,$3,$11,$4,$5,$6,$7,$8,$9,$10) RETURNING id`, t.DeviceID, t.Kind, t.Title, t.Args, t.Status, t.CreatedBy, t.CreatedAt, t.StartedAt, t.ExpiresAt, t.JobID, nonNil(t.TitleArgs)).Scan(&t.ID)
}

// Task loads one task.
func (s *Store) Task(ctx context.Context, id int64) (*DeviceTask, error) {
	return scanTask(s.db.QueryRow(ctx, `SELECT `+taskCols+` FROM device_tasks WHERE id=$1`, id))
}

// DeviceTasks lists the tasks of a device: all active ones and the newest
// finished ones.
func (s *Store) DeviceTasks(ctx context.Context, deviceID int64, finished int) ([]DeviceTask, error) {
	return s.tasks(ctx, `(SELECT `+taskCols+` FROM device_tasks WHERE device_id=$1 AND status IN ('queued', 'running'))
		UNION ALL (SELECT `+taskCols+` FROM device_tasks WHERE device_id=$1 AND status NOT IN ('queued', 'running') ORDER BY id DESC LIMIT $2)
		ORDER BY id DESC`, deviceID, finished)
}

// ActiveTasks counts the queued and running tasks and job runs of a device.
func (s *Store) ActiveTasks(ctx context.Context, deviceID int64) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM device_tasks WHERE device_id=$1 AND status IN ('queued', 'running'))
		+ (SELECT count(*) FROM script_job_devices jd JOIN script_jobs j ON j.id=jd.job_id WHERE jd.device_id=$1 AND jd.status='pending' AND j.expires_at > $2)`,
		deviceID, s.now()).Scan(&n)
	return n, err
}

// ClaimTasks marks the oldest queued task of each given device as running
// when the device has none running, and returns them.
func (s *Store) ClaimTasks(ctx context.Context, devices []int64) ([]DeviceTask, error) {
	now := s.now()
	return s.tasks(ctx, `WITH c AS (
		SELECT DISTINCT ON (t.device_id) t.id FROM device_tasks t
		WHERE t.status='queued' AND t.expires_at > $2 AND t.device_id = ANY($1)
		  AND NOT EXISTS (SELECT 1 FROM device_tasks r WHERE r.device_id=t.device_id AND r.status='running' AND r.job_id IS NULL)
		ORDER BY t.device_id, t.id)
		UPDATE device_tasks x SET status='running', started_at=$2 FROM c WHERE x.id=c.id AND x.status='queued'
		RETURNING x.id, x.device_id, x.kind, x.title, x.title_args, x.args, x.status, x.created_by, x.created_at, x.started_at, x.finished_at, x.expires_at, x.result, x.result_args, x.link, x.job_id`,
		devices, now)
}

// FinishTask stores the outcome of a running task.
func (s *Store) FinishTask(ctx context.Context, id int64, status, result string, resultArgs []string, link string) error {
	_, err := s.db.Exec(ctx, `UPDATE device_tasks SET status=$2, result=$3, result_args=$6, link=$4, finished_at=$5 WHERE id=$1 AND status='running'`,
		id, status, result, link, s.now(), nonNil(resultArgs))
	return err
}

// CancelQueuedTask cancels a task that has not started; it reports whether
// the task was still queued.
func (s *Store) CancelQueuedTask(ctx context.Context, id int64, by string) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE device_tasks SET status='cancelled', result='cancelled by %s', result_args=ARRAY[$2::text], finished_at=$3 WHERE id=$1 AND status='queued'`,
		id, by, s.now())
	return tag.RowsAffected() == 1, err
}

// ExpireTasks ends queued tasks whose device did not come online in time;
// failRunning (server start) also ends tasks that were in flight.
func (s *Store) ExpireTasks(ctx context.Context, failRunning bool) error {
	now := s.now()
	if _, err := s.db.Exec(ctx, `UPDATE device_tasks SET status='expired', finished_at=$1 WHERE status='queued' AND expires_at <= $1`, now); err != nil {
		return err
	}
	if failRunning {
		_, err := s.db.Exec(ctx, `UPDATE device_tasks SET status='failed', result='the server restarted during the task', finished_at=$1 WHERE status='running'`, now)
		return err
	}
	return nil
}

// PendingJobRun is a job that waits for a device.
type PendingJobRun struct {
	JobID     int64
	Name      string
	Shell     string
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// PendingJobRuns lists the jobs that wait for a device.
func (s *Store) PendingJobRuns(ctx context.Context, deviceID int64) ([]PendingJobRun, error) {
	rows, err := s.db.Query(ctx, `SELECT j.id, j.name, j.shell, j.created_by, j.created_at, j.expires_at FROM script_job_devices jd JOIN script_jobs j ON j.id=jd.job_id
		WHERE jd.device_id=$1 AND jd.status='pending' AND j.expires_at > $2 ORDER BY j.id`, deviceID, s.now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingJobRun
	for rows.Next() {
		var p PendingJobRun
		if err := rows.Scan(&p.JobID, &p.Name, &p.Shell, &p.CreatedBy, &p.CreatedAt, &p.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CancelJobRun cancels a waiting device of a job; it reports whether it
// was still waiting.
func (s *Store) CancelJobRun(ctx context.Context, jobID, deviceID int64) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE script_job_devices SET status='cancelled', updated_at=$3 WHERE job_id=$1 AND device_id=$2 AND status='pending'`,
		jobID, deviceID, s.now())
	return tag.RowsAffected() == 1, err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
