-- Activity of a device: every action the console asks of an agent is a
-- task that waits until the device is online, runs one at a time per
-- device, can be cancelled, and stays as history.
CREATE TABLE device_tasks (
    id          bigserial PRIMARY KEY,
    device_id   bigint NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind        text NOT NULL,
    title       text NOT NULL,
    title_args  text[] NOT NULL DEFAULT '{}',
    args        jsonb NOT NULL DEFAULT '{}',
    status      text NOT NULL CHECK (status IN ('queued', 'running', 'done', 'failed', 'cancelled', 'expired')),
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL,
    started_at  timestamptz,
    finished_at timestamptz,
    expires_at  timestamptz NOT NULL,
    result      text NOT NULL DEFAULT '',
    result_args text[] NOT NULL DEFAULT '{}',
    link        text NOT NULL DEFAULT '',
    job_id      bigint REFERENCES script_jobs(id) ON DELETE SET NULL
);
CREATE INDEX device_tasks_device ON device_tasks(device_id, id DESC);
CREATE INDEX device_tasks_queued ON device_tasks(device_id) WHERE status = 'queued';

-- A waiting device of a job can be cancelled.
ALTER TABLE script_job_devices DROP CONSTRAINT script_job_devices_status_check;
ALTER TABLE script_job_devices ADD CONSTRAINT script_job_devices_status_check CHECK (status IN ('pending', 'running', 'done', 'failed', 'expired', 'cancelled'));
