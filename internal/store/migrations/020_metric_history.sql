-- Network throughput in the minute samples (agents 0.11+), and hourly
-- summaries kept for 90 days: load and network per device, used space per
-- drive (for the history charts and the disk-full forecast).
ALTER TABLE device_samples
    ADD COLUMN rx real,
    ADD COLUMN tx real;

CREATE TABLE device_hourly (
    device_id bigint NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    hour      timestamptz NOT NULL,
    cpu_avg   real NOT NULL,
    cpu_max   real NOT NULL,
    mem_avg   real NOT NULL,
    mem_max   real NOT NULL,
    rx        real,
    tx        real,
    samples   integer NOT NULL,
    PRIMARY KEY (device_id, hour)
);

CREATE TABLE device_disk_hourly (
    device_id bigint NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    hour      timestamptz NOT NULL,
    drive     text NOT NULL,
    size      bigint NOT NULL,
    free      bigint NOT NULL,
    PRIMARY KEY (device_id, drive, hour)
);
CREATE INDEX device_disk_hourly_hour ON device_disk_hourly (hour);
CREATE INDEX device_hourly_hour ON device_hourly (hour);
