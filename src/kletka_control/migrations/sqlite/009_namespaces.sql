-- no-transaction
PRAGMA foreign_keys = OFF;

BEGIN;

ALTER TABLE users ADD COLUMN is_platform_admin INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN max_namespaces INTEGER;

CREATE TABLE namespaces (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL UNIQUE,
    personal_user_id  TEXT UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    quota_max_vms     INTEGER,
    quota_max_vcpu    INTEGER,
    quota_max_mem_mib INTEGER,
    created_by        TEXT,
    created_at        INTEGER NOT NULL
);

CREATE TABLE namespace_members (
    namespace_id TEXT NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role         TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    PRIMARY KEY (namespace_id, user_id)
);
CREATE INDEX idx_namespace_members_user ON namespace_members(user_id);

INSERT INTO namespaces (id, name, personal_user_id, created_by, created_at)
    SELECT id, 'u-' || substr(id, 1, 8) || substr(id, 10, 4), id, id, created_at FROM users;
INSERT INTO namespace_members (namespace_id, user_id, role, created_at)
    SELECT id, id, 'owner', created_at FROM users;

CREATE TABLE vms_new (
    id                TEXT PRIMARY KEY,
    namespace_id      TEXT NOT NULL REFERENCES namespaces(id),
    created_by        TEXT,
    name              TEXT NOT NULL,
    image             TEXT NOT NULL DEFAULT 'default',
    vcpu              INTEGER NOT NULL DEFAULT 2,
    memory_mib        INTEGER NOT NULL DEFAULT 1024,
    disk_mib          INTEGER NOT NULL DEFAULT 0,
    nat               INTEGER NOT NULL DEFAULT 1,
    status            TEXT NOT NULL DEFAULT 'pending',
    assigned_node     TEXT,
    created_at        INTEGER NOT NULL,
    idle_timeout_secs INTEGER,
    last_active_at    INTEGER,
    UNIQUE (namespace_id, name)
);
INSERT INTO vms_new (id, namespace_id, created_by, name, image, vcpu, memory_mib, disk_mib, nat,
                     status, assigned_node, created_at, idle_timeout_secs, last_active_at)
    SELECT id, owner_id, owner_id, name, image, vcpu, memory_mib, disk_mib, nat,
           status, assigned_node, created_at, idle_timeout_secs, last_active_at FROM vms;
DROP TABLE vms;
ALTER TABLE vms_new RENAME TO vms;
CREATE INDEX idx_vms_namespace ON vms(namespace_id);

ALTER TABLE audit_events ADD COLUMN namespace_id TEXT;
UPDATE audit_events SET namespace_id = user_id WHERE vm_id IS NOT NULL;
CREATE INDEX idx_audit_namespace ON audit_events(namespace_id, id);

COMMIT;

PRAGMA foreign_keys = ON;
