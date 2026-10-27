-- When the server first saw an update or a new version of a program: update
-- rings let devices wait a number of days after that.
CREATE TABLE update_first_seen (
    source     text NOT NULL, -- wu (Windows Update), winget, choco
    id         text NOT NULL,
    version    text NOT NULL DEFAULT '',
    first_seen timestamptz NOT NULL,
    PRIMARY KEY (source, id, version)
);

-- A restart a policy asks the signed-in user for; the server restarts the
-- computer itself at the deadline.
CREATE TABLE restart_requests (
    device_id    bigint PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    requested_at timestamptz NOT NULL,
    deadline     timestamptz NOT NULL
);
