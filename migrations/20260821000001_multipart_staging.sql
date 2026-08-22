-- Phase 10: durable encrypted client multipart staging metadata. Artifact bytes
-- live only in the separately configured S4-controlled staging bucket.
create table if not exists multipart_uploads (
    id uuid primary key,
    upload_id text not null unique,
    lifecycle text not null check (lifecycle in ('OPEN', 'ABORTED', 'EXPIRED')),
    tenant_id text not null,
    credential_policy_id text not null,
    bucket text not null,
    object_key text not null,
    metadata jsonb not null default '{}'::jsonb,
    tags jsonb not null default '{}'::jsonb,
    checksum_mode text,
    destination jsonb not null,
    plugin_snapshot jsonb not null,
    limits jsonb not null,
    staged_bytes bigint not null default 0 check (staged_bytes >= 0),
    reserved_bytes bigint not null default 0 check (reserved_bytes >= 0),
    expires_at_ms bigint not null,
    tombstone_until_ms bigint,
    created_at_ms bigint not null,
    updated_at_ms bigint not null
);
create index if not exists multipart_uploads_tenant_open_idx
    on multipart_uploads (tenant_id, lifecycle, expires_at_ms);
create index if not exists multipart_uploads_reconcile_idx
    on multipart_uploads (lifecycle, expires_at_ms) where lifecycle = 'OPEN';

create table if not exists multipart_part_attempts (
    id uuid primary key,
    upload_id text not null references multipart_uploads(upload_id) on delete cascade,
    part_number integer not null check (part_number between 1 and 10000),
    attempt integer not null check (attempt > 0),
    artifact_key text not null unique,
    etag text not null,
    checksum_sha256 text not null,
    size_bytes bigint not null check (size_bytes >= 0),
    reserved_bytes bigint not null default 0 check (reserved_bytes >= 0),
    lifecycle text not null check (lifecycle in ('PENDING', 'CURRENT', 'RETIRED')),
    is_current boolean not null,
    created_at_ms bigint not null,
    unique(upload_id, part_number, attempt)
);
create unique index if not exists multipart_current_part_idx
    on multipart_part_attempts (upload_id, part_number) where is_current;

-- Both rows are locked and updated in the same transaction before a part body
-- is consumed. They make tenant and account limits survive process restarts.
create table if not exists multipart_staging_quotas (
    scope text primary key,
    limit_bytes bigint not null check (limit_bytes > 0),
    staged_bytes bigint not null default 0 check (staged_bytes >= 0),
    reserved_bytes bigint not null default 0 check (reserved_bytes >= 0),
    updated_at_ms bigint not null
);

create table if not exists multipart_cleanup_audit (
    id uuid primary key,
    upload_id text not null references multipart_uploads(upload_id) on delete cascade,
    kind text not null,
    detail jsonb not null default '{}'::jsonb,
    created_at_ms bigint not null
);
create index if not exists multipart_cleanup_audit_upload_idx
    on multipart_cleanup_audit (upload_id, created_at_ms);
