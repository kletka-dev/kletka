PRAGMA foreign_keys = OFF;

CREATE TABLE jobs_new (
    id              TEXT PRIMARY KEY,
    vm_id           TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
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
INSERT INTO jobs_new SELECT * FROM jobs;
DROP TABLE jobs;
ALTER TABLE jobs_new RENAME TO jobs;

CREATE TABLE bids_new (
    job_id        TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    node_id       TEXT NOT NULL,
    free_vcpu     INTEGER NOT NULL,
    free_mem_mib  INTEGER NOT NULL,
    free_disk_mib INTEGER NOT NULL,
    score         INTEGER NOT NULL,
    created_at    INTEGER NOT NULL,
    PRIMARY KEY (job_id, node_id)
);
INSERT INTO bids_new SELECT * FROM bids;
DROP TABLE bids;
ALTER TABLE bids_new RENAME TO bids;

CREATE TABLE sessions_new (
    id         TEXT PRIMARY KEY,
    vm_id      TEXT NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    node_id    TEXT NOT NULL,
    kind_json  TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    expires_at INTEGER NOT NULL
);
INSERT INTO sessions_new SELECT * FROM sessions;
DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;

CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state);
CREATE INDEX IF NOT EXISTS idx_jobs_vm ON jobs(vm_id);
CREATE INDEX IF NOT EXISTS idx_vms_owner ON vms(owner_id);

PRAGMA foreign_keys = ON;
