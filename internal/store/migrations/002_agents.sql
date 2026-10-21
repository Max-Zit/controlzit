-- Agents authenticate with an ed25519 key (TLS client certificate);
-- key_id is the SHA-256 of the public key.
ALTER TABLE devices
    ADD COLUMN key_id        text,
    ADD COLUMN public_key    bytea,
    ADD COLUMN token_id      bigint REFERENCES enrollment_tokens(id) ON DELETE SET NULL,
    ADD COLUMN agent_version text NOT NULL DEFAULT '',
    ADD COLUMN os_version    text NOT NULL DEFAULT '',
    ADD COLUMN os_build      text NOT NULL DEFAULT '',
    ADD COLUMN last_user     text NOT NULL DEFAULT '',
    ADD COLUMN boot_time     timestamptz,
    ADD COLUMN remote_ip     text NOT NULL DEFAULT '',
    ADD COLUMN inventory     jsonb,
    ADD COLUMN inventory_at  timestamptz,
    ADD COLUMN connected     boolean NOT NULL DEFAULT false;
CREATE UNIQUE INDEX devices_key ON devices (key_id);
CREATE INDEX devices_site ON devices (site_id);
