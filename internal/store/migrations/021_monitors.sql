-- The last result of each monitor of a policy on a device: matching events
-- counted (kind 'event') or whether a process runs (kind 'process').
CREATE TABLE monitor_state (
    device_id  bigint NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind       text NOT NULL CHECK (kind IN ('event', 'process')),
    key        text NOT NULL,
    ok         boolean NOT NULL,
    count      integer NOT NULL DEFAULT 0,
    error      text NOT NULL DEFAULT '',
    checked_at timestamptz NOT NULL,
    PRIMARY KEY (device_id, kind, key)
);
