ALTER TABLE vms ADD COLUMN suspended INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vms ADD COLUMN idle_timeout_secs INTEGER;
ALTER TABLE vms ADD COLUMN last_active_at INTEGER;
UPDATE vms SET last_active_at = CAST(strftime('%s', 'now') AS INTEGER);
