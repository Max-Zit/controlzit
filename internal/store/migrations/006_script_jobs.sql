-- Script library, runs on many devices (jobs) and schedules.
CREATE TABLE scripts (
    id          bigserial PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    shell       text NOT NULL CHECK (shell IN ('powershell', 'cmd')),
    body        text NOT NULL,
    timeout     int NOT NULL,
    updated_by  text NOT NULL,
    updated_at  timestamptz NOT NULL
);

CREATE TABLE script_schedules (
    id         bigserial PRIMARY KEY,
    script_id  bigint NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
    target     jsonb NOT NULL,
    days       int[] NOT NULL,
    minute     int NOT NULL CHECK (minute >= 0 AND minute < 1440), -- minute of the day, server time
    enabled    boolean NOT NULL DEFAULT true,
    created_by text NOT NULL,
    last_fired timestamptz
);

-- A job is one script (a copy, so later edits do not change it) for many
-- devices; devices that are offline run it when they connect, until it
-- expires.
CREATE TABLE script_jobs (
    id          bigserial PRIMARY KEY,
    script_id   bigint REFERENCES scripts(id) ON DELETE SET NULL,
    schedule_id bigint REFERENCES script_schedules(id) ON DELETE SET NULL,
    name        text NOT NULL,
    shell       text NOT NULL,
    body        text NOT NULL,
    timeout     int NOT NULL,
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL
);

CREATE TABLE script_job_devices (
    job_id     bigint NOT NULL REFERENCES script_jobs(id) ON DELETE CASCADE,
    device_id  bigint NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    status     text NOT NULL CHECK (status IN ('pending', 'running', 'done', 'failed', 'expired')),
    run_id     bigint REFERENCES script_runs(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (job_id, device_id)
);
CREATE INDEX script_job_devices_pending ON script_job_devices(device_id) WHERE status = 'pending';

ALTER TABLE script_runs ADD COLUMN job_id bigint REFERENCES script_jobs(id) ON DELETE SET NULL;
