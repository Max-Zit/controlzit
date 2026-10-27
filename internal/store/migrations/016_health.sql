-- The last result of each network check of a device (policy checks, run
-- by the agent every minute).
CREATE TABLE net_check_state (
    device_id     bigint NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name          text NOT NULL,
    kind          text NOT NULL,
    target        text NOT NULL,
    ok            boolean NOT NULL,
    ms            integer NOT NULL DEFAULT 0,
    error         text NOT NULL DEFAULT '',
    cert_days     integer NOT NULL DEFAULT 0,
    checked_at    timestamptz NOT NULL,
    failing_since timestamptz,
    PRIMARY KEY (device_id, name)
);

-- The health of a device's physical disks and RAID arrays (hourly).
CREATE TABLE device_disk_health (
    device_id    bigint PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    health       jsonb NOT NULL,
    collected_at timestamptz NOT NULL
);
