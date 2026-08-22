-- Phase 11: durable completion lease, request fingerprint, and immutable
-- completion result. Existing Phase 10 uploads remain OPEN until completed.
alter table multipart_uploads
    drop constraint if exists multipart_uploads_lifecycle_check;
alter table multipart_uploads
    add constraint multipart_uploads_lifecycle_check
    check (lifecycle in ('OPEN', 'COMPLETING', 'COMPLETED', 'ABORTED', 'EXPIRED'));

alter table multipart_uploads
    add column if not exists complete_request_fingerprint text,
    add column if not exists completion_lease_owner text,
    add column if not exists completion_lease_expires_at_ms bigint,
    add column if not exists completion_fencing_token bigint not null default 0
        check (completion_fencing_token >= 0),
    add column if not exists completion_result jsonb;

create index if not exists multipart_uploads_completion_lease_idx
    on multipart_uploads (lifecycle, completion_lease_expires_at_ms)
    where lifecycle = 'COMPLETING';
