CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,
    quota_max_vms     INTEGER NOT NULL DEFAULT 5,
    quota_max_vcpu    INTEGER NOT NULL DEFAULT 8,
    quota_max_mem_mib INTEGER NOT NULL DEFAULT 8192,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id),
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS vms (
    id            TEXT PRIMARY KEY,
    owner_id      TEXT NOT NULL REFERENCES users(id),
    name          TEXT NOT NULL,
    image         TEXT NOT NULL DEFAULT 'default',
    vcpu          INTEGER NOT NULL DEFAULT 2,
    memory_mib    INTEGER NOT NULL DEFAULT 1024,
    disk_mib      INTEGER NOT NULL DEFAULT 0,
    nat           INTEGER NOT NULL DEFAULT 1,
    status        TEXT NOT NULL DEFAULT 'pending',
    assigned_node TEXT,
    created_at    INTEGER NOT NULL,
    UNIQUE (owner_id, name)
);

CREATE TABLE IF NOT EXISTS jobs (
    id              TEXT PRIMARY KEY,
    vm_id           TEXT NOT NULL REFERENCES vms(id),
    user_id         TEXT NOT NULL REFERENCES users(id),
    kind            TEXT NOT NULL,
    spec_json       TEXT,
    state           TEXT NOT NULL DEFAULT 'bidding',
    assigned_node   TEXT,
    assigned_at     INTEGER,
    completed_at    INTEGER,
    retries         INTEGER NOT NULL DEFAULT 0,
    error           TEXT,
    idempotency_key TEXT,
    expires_at      INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    UNIQUE (user_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS bids (
    job_id        TEXT NOT NULL REFERENCES jobs(id),
    node_id       TEXT NOT NULL,
    free_vcpu     INTEGER NOT NULL,
    free_mem_mib  INTEGER NOT NULL,
    free_disk_mib INTEGER NOT NULL,
    score         INTEGER NOT NULL,
    created_at    INTEGER NOT NULL,
    PRIMARY KEY (job_id, node_id)
);

CREATE TABLE IF NOT EXISTS nodes (
    node_id        TEXT PRIMARY KEY,
    last_seen      INTEGER NOT NULL,
    running_vm_ids TEXT NOT NULL DEFAULT '[]',
    free_vcpu      INTEGER NOT NULL DEFAULT 0,
    free_mem_mib   INTEGER NOT NULL DEFAULT 0,
    free_disk_mib  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    vm_id      TEXT NOT NULL REFERENCES vms(id),
    node_id    TEXT NOT NULL,
    kind_json  TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state);
CREATE INDEX IF NOT EXISTS idx_jobs_vm ON jobs(vm_id);
CREATE INDEX IF NOT EXISTS idx_vms_owner ON vms(owner_id);
