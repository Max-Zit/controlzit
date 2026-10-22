-- Windows Update state reported by the agents, and the day the automatic
-- installation last ran for a device.
CREATE TABLE device_patches (
    device_id      bigint PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    report         jsonb NOT NULL,
    updated_at     timestamptz NOT NULL,
    auto_install_on date
);
