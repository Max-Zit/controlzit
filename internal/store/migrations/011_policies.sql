-- Policies: named settings (Windows Update, required software, alert rules,
-- scheduled automations) assigned to customers, sites or devices. For each
-- part, the most specific assignment that sets it wins (device, site,
-- customer, then the server's own settings).
CREATE TABLE policies (
    id          bigserial PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    settings    jsonb NOT NULL DEFAULT '{}',
    updated_by  text NOT NULL,
    updated_at  timestamptz NOT NULL
);

-- One policy per customer, site or device.
CREATE TABLE policy_assignments (
    target_type text NOT NULL CHECK (target_type IN ('customer', 'site', 'device')),
    target_id   bigint NOT NULL,
    policy_id   bigint NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    assigned_by text NOT NULL,
    assigned_at timestamptz NOT NULL,
    PRIMARY KEY (target_type, target_id)
);
CREATE INDEX policy_assignments_policy ON policy_assignments(policy_id);

-- When a policy last started something on a device (installing a required
-- program) or for a time slot (an automation), so it does not repeat.
CREATE TABLE policy_marks (
    key       text PRIMARY KEY,
    marked_at timestamptz NOT NULL
);
