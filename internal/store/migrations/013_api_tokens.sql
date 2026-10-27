-- Personal API tokens: a token acts as its user with a role no higher than
-- the user's (and the user's customers); only its hash is stored.
CREATE TABLE api_tokens (
    id           bigserial PRIMARY KEY,
    user_id      bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         text NOT NULL,
    role         text NOT NULL CHECK (role IN ('admin', 'technician', 'readonly')),
    token_hash   text NOT NULL UNIQUE,
    created_at   timestamptz NOT NULL,
    expires_at   timestamptz,
    last_used_at timestamptz
);
CREATE INDEX api_tokens_user ON api_tokens(user_id);
