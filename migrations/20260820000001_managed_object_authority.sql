-- Logical-key authority and durable repair work for managed object storage.
-- Physical objects remain in configured S3-compatible backends.
create table if not exists managed_object_authorities (
    tenant_id text not null,
    bucket text not null,
    logical_key text not null,
    generation uuid not null,
    digest text not null,
    size_bytes bigint not null check (size_bytes >= 0),
    metadata jsonb not null default '{}'::jsonb,
    placement_version bigint not null check (placement_version > 0),
    primary_backend_id text not null,
    replica_backend_id text,
    primary_status text not null check (primary_status in ('READY', 'REPAIR_PENDING', 'ABSENT')),
    replica_status text not null check (replica_status in ('READY', 'REPAIR_PENDING', 'ABSENT')),
    tombstone boolean not null default false,
    cas_version bigint not null check (cas_version > 0),
    created_at_ms bigint not null,
    updated_at_ms bigint not null,
    primary key (tenant_id, bucket, logical_key)
);

create index if not exists managed_object_authorities_generation_idx
    on managed_object_authorities (generation);

create table if not exists managed_object_repairs (
    id uuid primary key,
    kind text not null check (kind in ('REPLICA', 'PLACEMENT', 'DELETE_GENERATION')),
    state text not null check (state in ('PENDING', 'LEASED', 'DONE')),
    tenant_id text not null,
    bucket text not null,
    logical_key text not null,
    generation uuid not null,
    digest text not null,
    size_bytes bigint not null check (size_bytes >= 0),
    metadata jsonb not null default '{}'::jsonb,
    physical_key text not null,
    source_backend_id text,
    target_backend_id text not null,
    target_role text not null check (target_role in ('PRIMARY', 'REPLICA', 'CLEANUP')),
    placement_version bigint not null check (placement_version > 0),
    placement_primary_backend_id text,
    placement_replica_backend_id text,
    attempts integer not null default 0 check (attempts >= 0),
    lease_owner text,
    lease_expires_at_ms bigint,
    last_error text,
    created_at_ms bigint not null,
    updated_at_ms bigint not null,
    unique (kind, generation, target_backend_id)
);

create index if not exists managed_object_repairs_claim_idx
    on managed_object_repairs (state, updated_at_ms)
    where state in ('PENDING', 'LEASED');
