ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_vm_id_fkey;
ALTER TABLE jobs
    ADD CONSTRAINT jobs_vm_id_fkey
    FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE;

ALTER TABLE bids DROP CONSTRAINT IF EXISTS bids_job_id_fkey;
ALTER TABLE bids
    ADD CONSTRAINT bids_job_id_fkey
    FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE;

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_vm_id_fkey;
ALTER TABLE sessions
    ADD CONSTRAINT sessions_vm_id_fkey
    FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE;
