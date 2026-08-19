-- Durable destination-operation journal. These relations are additive and are
-- intentionally independent from request handlers until streaming writes ship.
create table if not exists object_operations (
    id uuid primary key,
    state text not null check (state in (
        'INTENT', 'OPEN', 'COMPLETING', 'COMMIT_UNKNOWN', 'COMMITTED',
        'ABORTING', 'PROVEN_ABORTED'
    )),
    backend_id text not null,
    bucket text not null,
    logical_key text not null,
    physical_key text not null,
    expected_digest text,
    expected_size bigint check (expected_size is null or expected_size >= 0),
    expected_metadata jsonb not null default '{}'::jsonb,
    upload_id text,
    committed_etag text,
    committed_version_id text,
    lease_owner text,
    lease_expires_at_ms bigint,
    created_at_ms bigint not null,
    updated_at_ms bigint not null
);

create index if not exists object_operations_reconcile_idx
    on object_operations (state, updated_at_ms)
    where state not in ('COMMITTED', 'PROVEN_ABORTED');

create index if not exists object_operations_destination_idx
    on object_operations (backend_id, bucket, physical_key, created_at_ms);

create table if not exists object_operation_parts (
    operation_id uuid not null references object_operations(id) on delete cascade,
    part_number integer not null check (part_number between 1 and 10000),
    etag text not null,
    size_bytes bigint not null check (size_bytes >= 0),
    digest text not null,
    created_at_ms bigint not null,
    primary key (operation_id, part_number)
);

create table if not exists object_operation_evidence (
    id uuid primary key,
    operation_id uuid not null references object_operations(id) on delete cascade,
    kind text not null,
    detail jsonb not null default '{}'::jsonb,
    created_at_ms bigint not null
);

create index if not exists object_operation_evidence_operation_idx
    on object_operation_evidence (operation_id, created_at_ms);
