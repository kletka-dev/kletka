ALTER TABLE users ADD COLUMN is_platform_admin BIGINT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN max_namespaces BIGINT;

CREATE TABLE namespaces (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL UNIQUE,
    personal_user_id  TEXT UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    quota_max_vms     BIGINT,
    quota_max_vcpu    BIGINT,
    quota_max_mem_mib BIGINT,
    created_by        TEXT,
    created_at        BIGINT NOT NULL
);

CREATE TABLE namespace_members (
    namespace_id TEXT NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role         TEXT NOT NULL,
    created_at   BIGINT NOT NULL,
    PRIMARY KEY (namespace_id, user_id)
);
CREATE INDEX idx_namespace_members_user ON namespace_members(user_id);

INSERT INTO namespaces (id, name, personal_user_id, created_by, created_at)
    SELECT id, 'u-' || substr(id, 1, 8) || substr(id, 10, 4), id, id, created_at FROM users;
INSERT INTO namespace_members (namespace_id, user_id, role, created_at)
    SELECT id, id, 'owner', created_at FROM users;

ALTER TABLE vms DROP CONSTRAINT IF EXISTS vms_owner_id_fkey;
ALTER TABLE vms RENAME COLUMN owner_id TO namespace_id;
ALTER TABLE vms ADD COLUMN created_by TEXT;
UPDATE vms SET created_by = namespace_id;
ALTER TABLE vms
    ADD CONSTRAINT vms_namespace_id_fkey
    FOREIGN KEY (namespace_id) REFERENCES namespaces(id);
DROP INDEX IF EXISTS idx_vms_owner;
CREATE INDEX idx_vms_namespace ON vms(namespace_id);

ALTER TABLE audit_events ADD COLUMN namespace_id TEXT;
UPDATE audit_events SET namespace_id = user_id WHERE vm_id IS NOT NULL;
CREATE INDEX idx_audit_namespace ON audit_events(namespace_id, id);
