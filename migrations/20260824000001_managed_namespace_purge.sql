-- Exact managed-namespace lifecycle and physical-version ledger.
-- A clean deployment baseline is required: provider buckets and managed DB
-- metadata must be empty before this migration is enabled.
create table if not exists managed_namespaces (
    tenant_id text primary key,
    epoch bigint not null check (epoch > 0),
    state text not null check (state in ('ACTIVE', 'PURGING')),
    purge_operation_id uuid,
    created_at_ms bigint not null,
    updated_at_ms bigint not null
);

create table if not exists managed_namespace_purges (
    operation_id uuid primary key,
    tenant_id text not null,
    epoch bigint not null check (epoch > 0),
    state text not null check (state in ('RUNNING', 'BLOCKED', 'COMPLETE')),
    blocked_reason text,
    deleted_versions bigint not null default 0 check (deleted_versions >= 0),
    created_at_ms bigint not null,
    updated_at_ms bigint not null,
    completed_at_ms bigint,
    unique (tenant_id, epoch)
);

create table if not exists managed_physical_write_intents (
    intent_id uuid primary key,
    tenant_id text not null,
    epoch bigint not null check (epoch > 0),
    backend_id text not null,
    backend_fingerprint text not null,
    provider_bucket text not null,
    physical_key text not null,
    versioning_mode text not null check (versioning_mode in ('UNVERSIONED', 'ENABLED', 'SUSPENDED', 'UNKNOWN')),
    versioning_capability text not null check (versioning_capability in ('UNSUPPORTED', 'OPTIONAL', 'REQUIRED')),
    state text not null default 'PENDING' check (state in ('PENDING', 'BLOCKED')),
    last_error text,
    lease_owner text not null,
    lease_token uuid not null,
    lease_expires_at_ms bigint not null,
    created_at_ms bigint not null,
    updated_at_ms bigint not null
);

create index if not exists managed_physical_write_intents_tenant_idx
    on managed_physical_write_intents (tenant_id, epoch);

create table if not exists managed_physical_object_versions (
    tenant_id text not null,
    backend_id text not null,
    backend_fingerprint text not null,
    provider_bucket text not null,
    physical_key text not null,
    versioning_mode text not null check (versioning_mode in ('UNVERSIONED', 'ENABLED', 'SUSPENDED', 'UNKNOWN')),
    versioning_capability text not null check (versioning_capability in ('UNSUPPORTED', 'OPTIONAL', 'REQUIRED')),
    write_operation_id uuid not null,
    -- Empty string denotes the exact current unversioned object.
    version_id text not null,
    epoch bigint not null check (epoch > 0),
    state text not null check (state in ('LIVE', 'PURGE_PENDING', 'PURGE_BLOCKED')),
    purge_operation_id uuid,
    last_error text,
    created_at_ms bigint not null,
    updated_at_ms bigint not null,
    primary key (tenant_id, backend_id, provider_bucket, physical_key, version_id)
);

create index if not exists managed_physical_object_versions_purge_idx
    on managed_physical_object_versions (purge_operation_id, state, updated_at_ms);

create index if not exists managed_physical_object_versions_operation_idx
    on managed_physical_object_versions (write_operation_id);

alter table multipart_uploads
    add column if not exists namespace_epoch bigint check (namespace_epoch is null or namespace_epoch > 0);

alter table managed_object_repairs
    add column if not exists namespace_epoch bigint not null default 1 check (namespace_epoch > 0),
    add column if not exists authority_cas_version bigint not null default 0 check (authority_cas_version >= 0);

create table if not exists managed_multipart_activities (
    upload_id text primary key,
    tenant_id text not null,
    namespace_epoch bigint not null check (namespace_epoch > 0),
    state text not null check (state in ('REGISTERING', 'ACTIVE')),
    registration_expires_at_ms bigint,
    created_at_ms bigint not null,
    updated_at_ms bigint not null
);

create index if not exists managed_multipart_activities_tenant_epoch_idx
    on managed_multipart_activities (tenant_id, namespace_epoch);

-- Managed write intents depend on the transaction journal retaining every
-- provider version observed during multipart metadata rewrite.
alter table object_operations
    add column if not exists committed_superseded_version_ids jsonb not null default '[]'::jsonb,
    add column if not exists committed_version_history_complete boolean not null default true,
    add column if not exists tenant_id text,
    add column if not exists namespace_epoch bigint check (namespace_epoch is null or namespace_epoch > 0);

create index if not exists object_operations_tenant_epoch_idx
    on object_operations (tenant_id, namespace_epoch, state, updated_at_ms)
    where tenant_id is not null;
