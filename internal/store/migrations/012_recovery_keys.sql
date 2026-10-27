-- BitLocker recovery keys collected from the agents (sealed with the
-- server's secret key; shown only to administrators, each time audited).
CREATE TABLE device_recovery_keys (
    device_id    bigint NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    protector_id text NOT NULL,
    volume       text NOT NULL,
    sealed       text NOT NULL,
    first_seen   timestamptz NOT NULL,
    last_seen    timestamptz NOT NULL,
    PRIMARY KEY (device_id, protector_id)
);
