CREATE TABLE IF NOT EXISTS oauth_accounts (
    provider     TEXT NOT NULL,
    provider_uid TEXT NOT NULL,
    user_id      TEXT NOT NULL REFERENCES users(id),
    created_at   BIGINT NOT NULL,
    PRIMARY KEY (provider, provider_uid)
);

CREATE TABLE IF NOT EXISTS oauth_states (
    state      TEXT PRIMARY KEY,
    provider   TEXT NOT NULL,
    redirect   TEXT NOT NULL DEFAULT '',
    token      TEXT NOT NULL DEFAULT '',
    email      TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL
);
