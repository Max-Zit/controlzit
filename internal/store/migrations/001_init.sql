CREATE TABLE settings (
    key   text PRIMARY KEY,
    value jsonb NOT NULL
);

CREATE TABLE customers (
    id         bigserial PRIMARY KEY,
    name       text NOT NULL,
    notes      text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX customers_name ON customers (lower(name));

CREATE TABLE sites (
    id          bigserial PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers(id),
    name        text NOT NULL,
    address     text NOT NULL DEFAULT '',
    notes       text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX sites_name ON sites (customer_id, lower(name));

-- Managed machines; filled by agent enrollment.
CREATE TABLE devices (
    id           bigserial PRIMARY KEY,
    site_id      bigint NOT NULL REFERENCES sites(id),
    agent_id     uuid NOT NULL UNIQUE,
    hostname     text NOT NULL,
    os           text NOT NULL DEFAULT '',
    enrolled_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz
);

CREATE TABLE users (
    id                   bigserial PRIMARY KEY,
    username             text NOT NULL,
    display_name         text NOT NULL DEFAULT '',
    password_hash        text NOT NULL,
    role                 text NOT NULL CHECK (role IN ('admin', 'technician', 'readonly')),
    -- technicians and read-only users see all customers or only the listed ones
    all_customers        boolean NOT NULL DEFAULT false,
    totp_secret          text NOT NULL DEFAULT '',
    totp_enabled         boolean NOT NULL DEFAULT false,
    totp_last_step       bigint NOT NULL DEFAULT 0,
    recovery_codes       text[] NOT NULL DEFAULT '{}',
    must_change_password boolean NOT NULL DEFAULT false,
    disabled             boolean NOT NULL DEFAULT false,
    lang                 text NOT NULL DEFAULT '',
    created_at           timestamptz NOT NULL DEFAULT now(),
    last_login_at        timestamptz
);
CREATE UNIQUE INDEX users_username ON users (lower(username));

CREATE TABLE user_customers (
    user_id     bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, customer_id)
);

-- Sign-in sessions; only the SHA-256 of the cookie value is stored.
-- stage 'mfa' is a password-verified sign-in waiting for the second factor.
CREATE TABLE sessions (
    token_hash text PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stage      text NOT NULL CHECK (stage IN ('mfa', 'full')),
    created_at timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    ip         text NOT NULL DEFAULT '',
    user_agent text NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user ON sessions (user_id);

-- Tokens an agent installer uses to enroll a device into a site.
CREATE TABLE enrollment_tokens (
    id         bigserial PRIMARY KEY,
    site_id    bigint NOT NULL REFERENCES sites(id),
    token_hash text NOT NULL UNIQUE,
    label      text NOT NULL DEFAULT '',
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    max_uses   int NOT NULL,
    uses       int NOT NULL DEFAULT 0,
    revoked_at timestamptz
);

-- Addresses blocked after failed sign-ins.
CREATE TABLE login_blocks (
    ip         text PRIMARY KEY,
    until      timestamptz NOT NULL,
    strikes    int NOT NULL,
    reason     text NOT NULL,
    updated_at timestamptz NOT NULL
);

-- Append-only, hash-chained audit log: hash = SHA-256(prev_hash, fields).
CREATE TABLE audit_log (
    id        bigserial PRIMARY KEY,
    at        timestamptz NOT NULL,
    username  text NOT NULL,
    ip        text NOT NULL,
    action    text NOT NULL,
    target    text NOT NULL,
    detail    text NOT NULL,
    prev_hash text NOT NULL,
    hash      text NOT NULL
);
