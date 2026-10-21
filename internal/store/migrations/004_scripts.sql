-- Scripts run on devices from the console, with their full output (the
-- audit log keeps the script and the start of the output).
CREATE TABLE script_runs (
    id          bigserial PRIMARY KEY,
    device_id   bigint NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    username    text NOT NULL,
    shell       text NOT NULL CHECK (shell IN ('powershell', 'cmd')),
    script      text NOT NULL,
    started_at  timestamptz NOT NULL,
    duration_ms bigint NOT NULL DEFAULT 0,
    exit_code   int,
    timed_out   boolean NOT NULL DEFAULT false,
    truncated   boolean NOT NULL DEFAULT false,
    output      text NOT NULL DEFAULT '',
    error       text NOT NULL DEFAULT ''
);
CREATE INDEX script_runs_device ON script_runs(device_id, id DESC);
