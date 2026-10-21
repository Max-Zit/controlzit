-- Latest metrics of a device (heartbeat) and a short history for charts
-- and sustained-load rules.
ALTER TABLE devices
    ADD COLUMN metrics    jsonb,
    ADD COLUMN metrics_at timestamptz,
    ADD COLUMN security   jsonb,
    ADD COLUMN stopped_auto text[];

CREATE TABLE device_samples (
    device_id bigint NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    at        timestamptz NOT NULL,
    cpu       real NOT NULL,
    mem       real NOT NULL,
    PRIMARY KEY (device_id, at)
);

-- An alert is open while its condition holds; key tells apart alerts of
-- the same kind (the drive letter, the service name).
CREATE TABLE alerts (
    id          bigserial PRIMARY KEY,
    device_id   bigint NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind        text NOT NULL,
    key         text NOT NULL DEFAULT '',
    severity    text NOT NULL CHECK (severity IN ('warning', 'critical')),
    message     text NOT NULL,
    opened_at   timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,
    resolved_at timestamptz,
    acked_by    text,
    acked_at    timestamptz,
    notified    boolean NOT NULL DEFAULT false
);
CREATE UNIQUE INDEX alerts_open ON alerts (device_id, kind, key) WHERE resolved_at IS NULL;
CREATE INDEX alerts_recent ON alerts (opened_at DESC);
