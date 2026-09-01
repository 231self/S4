-- Customer-level managed mutations, capacity accounting, and opaque list
-- cursors. Physical provider journals remain independent child operations.
-- The pre-operation schema did not persist enough information to reconstruct
-- exact physical allocation or immutable provider identity. Refuse an unsafe
-- upgrade instead of silently resetting usage for an existing managed tenant.
do $$
begin
    if exists (select 1 from managed_object_authorities limit 1)
        or exists (select 1 from managed_physical_write_intents limit 1)
        or exists (select 1 from managed_physical_object_versions limit 1) then
        raise exception using
            errcode = '55000',
            message = 'cannot enable managed store operations with existing managed authority or physical ledger state';
    end if;
end;
$$;

alter table managed_namespaces
    add column if not exists routing_epoch bigint not null default 1
        check (routing_epoch > 0);

-- Provider storage identity is immutable for the lifetime of a physical row.
-- The stable instance ID is routing identity only; credential epochs may move
-- forward only when every storage-location field remains equal.
alter table managed_physical_write_intents
    drop column backend_fingerprint,
    add column provider_kind text not null
        check (char_length(provider_kind) between 1 and 128),
    add column provider_instance_id text not null
        check (char_length(provider_instance_id) between 1 and 128),
    add column provider_account_id text not null
        check (char_length(provider_account_id) between 1 and 256),
    add column canonical_endpoint text not null
        check (char_length(canonical_endpoint) between 1 and 2048),
    add column provider_region text not null
        check (char_length(provider_region) between 1 and 128),
    add column credential_epoch bigint not null check (credential_epoch > 0);

alter table managed_physical_object_versions
    drop column backend_fingerprint,
    add column provider_kind text not null
        check (char_length(provider_kind) between 1 and 128),
    add column provider_instance_id text not null
        check (char_length(provider_instance_id) between 1 and 128),
    add column provider_account_id text not null
        check (char_length(provider_account_id) between 1 and 256),
    add column canonical_endpoint text not null
        check (char_length(canonical_endpoint) between 1 and 2048),
    add column provider_region text not null
        check (char_length(provider_region) between 1 and 128),
    add column credential_epoch bigint not null check (credential_epoch > 0);

-- Ordinary SeaORM ordering now has the bytewise semantics required by S3.
alter table managed_object_authorities
    alter column logical_key type text collate "C",
    add column primary_version_id text;

create index if not exists managed_object_authorities_list_idx
    on managed_object_authorities (tenant_id, bucket, logical_key)
    where tombstone = false;

create table if not exists managed_logical_operations (
    operation_id uuid primary key,
    receipt_id uuid not null unique,
    tenant_id text not null,
    bucket text not null,
    logical_key text collate "C" not null,
    operation_kind text not null check (operation_kind in ('PUT', 'DELETE')),
    generation uuid not null,
    namespace_epoch bigint not null check (namespace_epoch > 0),
    routing_epoch bigint not null check (routing_epoch > 0),
    expected_authority_cas bigint check (
        expected_authority_cas is null or expected_authority_cas > 0
    ),
    prior_logical_size bigint not null check (prior_logical_size >= 0),
    primary_child_operation_id uuid not null unique,
    backend_id text not null,
    provider_bucket text not null,
    physical_key text not null,
    expected_output_digest text,
    expected_output_size bigint check (
        expected_output_size is null or expected_output_size >= 0
    ),
    source_bytes bigint check (source_bytes is null or source_bytes >= 0),
    processed_bytes bigint check (processed_bytes is null or processed_bytes >= 0),
    reserved_physical_bytes bigint not null default 0
        check (reserved_physical_bytes >= 0),
    committed_physical_bytes bigint not null default 0
        check (committed_physical_bytes >= 0),
    released_physical_bytes bigint not null default 0
        check (
            released_physical_bytes >= 0
            and released_physical_bytes <= committed_physical_bytes
        ),
    state text not null check (state in (
        'INTENT', 'OPEN', 'COMPLETING', 'COMMIT_UNKNOWN', 'COMMITTED',
        'PROVEN_ABORTED'
    )),
    committed_authority_version bigint check (
        committed_authority_version is null or committed_authority_version > 0
    ),
    occurred_at_ms bigint not null check (occurred_at_ms >= 0),
    rate_version integer not null check (rate_version > 0),
    usage_route text not null check (char_length(usage_route) between 1 and 128),
    request_kind text not null check (request_kind in ('write', 'read')),
    max_processed_bytes bigint not null check (max_processed_bytes >= 0),
    usage_evidence jsonb not null default '{}'::jsonb,
    settlement_state text not null default 'PENDING'
        check (settlement_state in ('PENDING', 'SETTLED', 'RELEASED')),
    last_error_class text,
    created_at_ms bigint not null,
    updated_at_ms bigint not null,
    committed_at_ms bigint,
    aborted_at_ms bigint,
    check (
        (state = 'COMMITTED'
            and committed_authority_version is not null
            and committed_at_ms is not null
            and aborted_at_ms is null)
        or (state = 'PROVEN_ABORTED'
            and committed_authority_version is null
            and committed_at_ms is null
            and aborted_at_ms is not null)
        or (state not in ('COMMITTED', 'PROVEN_ABORTED')
            and committed_authority_version is null
            and committed_at_ms is null
            and aborted_at_ms is null)
    ),
    check (
        (operation_kind = 'PUT' and usage_route = 'PutObject')
        or (operation_kind = 'DELETE' and usage_route = 'DeleteObject')
    ),
    check (request_kind = 'write')
);

create index if not exists managed_logical_operations_reconcile_idx
    on managed_logical_operations (state, updated_at_ms)
    where state not in ('COMMITTED', 'PROVEN_ABORTED');

create index if not exists managed_logical_operations_workspace_idx
    on managed_logical_operations (tenant_id, state, updated_at_ms);

create index if not exists managed_logical_operations_generation_idx
    on managed_logical_operations (tenant_id, generation);

create table if not exists managed_workspace_usage (
    tenant_id text primary key,
    visible_logical_bytes bigint not null default 0
        check (visible_logical_bytes >= 0),
    physical_allocated_bytes bigint not null default 0
        check (physical_allocated_bytes >= 0),
    reserved_bytes bigint not null default 0 check (reserved_bytes >= 0),
    visible_limit_bytes bigint not null default 1073741824
        check (visible_limit_bytes = 1073741824),
    replacement_headroom_bytes bigint not null default 134217728
        check (replacement_headroom_bytes = 134217728),
    active_operation_id uuid references managed_logical_operations(operation_id)
        on update restrict on delete restrict,
    version bigint not null default 1 check (version > 0),
    created_at_ms bigint not null,
    updated_at_ms bigint not null,
    check (visible_logical_bytes <= visible_limit_bytes),
    check (
        physical_allocated_bytes + reserved_bytes
            <= visible_limit_bytes + replacement_headroom_bytes
    )
);

create table if not exists managed_list_cursors (
    cursor_id uuid primary key,
    predecessor_cursor_id uuid unique references managed_list_cursors(cursor_id)
        on update restrict on delete cascade,
    tenant_id text not null,
    namespace_epoch bigint not null check (namespace_epoch > 0),
    routing_epoch bigint not null check (routing_epoch > 0),
    bucket text not null,
    prefix text not null,
    delimiter text,
    list_version text not null check (list_version in ('V1', 'V2')),
    last_key text collate "C",
    last_common_prefix text collate "C",
    response_state bytea not null check (octet_length(response_state) <= 65536),
    response_state_bytes bigint not null check (
        response_state_bytes = octet_length(response_state)
        and response_state_bytes between 0 and 65536
    ),
    final_page boolean not null,
    state text not null default 'ACTIVE' check (state in ('ACTIVE', 'USED')),
    created_at_ms bigint not null,
    expires_at_ms bigint not null,
    first_used_at_ms bigint,
    check (expires_at_ms > created_at_ms),
    check (
        (state = 'ACTIVE' and first_used_at_ms is null)
        or (state = 'USED' and first_used_at_ms is not null)
    )
);

create index if not exists managed_list_cursors_expiry_idx
    on managed_list_cursors (expires_at_ms, cursor_id);

create index if not exists managed_list_cursors_workspace_idx
    on managed_list_cursors (tenant_id, expires_at_ms);

-- Pricing identity and request identity are historical facts, not mutable
-- operation state. Enforce that boundary even for future repository callers.
create or replace function s4_managed_logical_evidence_immutable()
returns trigger language plpgsql as $$
begin
    if (new.receipt_id, new.tenant_id, new.bucket, new.logical_key,
        new.operation_kind, new.generation, new.namespace_epoch,
        new.routing_epoch, new.expected_authority_cas,
        new.prior_logical_size, new.primary_child_operation_id,
        new.backend_id, new.provider_bucket, new.physical_key,
        new.occurred_at_ms, new.rate_version, new.usage_route,
        new.request_kind, new.max_processed_bytes, new.created_at_ms)
       is distinct from
       (old.receipt_id, old.tenant_id, old.bucket, old.logical_key,
        old.operation_kind, old.generation, old.namespace_epoch,
        old.routing_epoch, old.expected_authority_cas,
        old.prior_logical_size, old.primary_child_operation_id,
        old.backend_id, old.provider_bucket, old.physical_key,
        old.occurred_at_ms, old.rate_version, old.usage_route,
        old.request_kind, old.max_processed_bytes, old.created_at_ms) then
        raise exception 'managed logical operation identity is immutable';
    end if;
    return new;
end;
$$;

drop trigger if exists managed_logical_evidence_immutable
    on managed_logical_operations;
create trigger managed_logical_evidence_immutable
before update on managed_logical_operations
for each row execute function s4_managed_logical_evidence_immutable();

create or replace function s4_managed_cursor_payload_immutable()
returns trigger language plpgsql as $$
begin
    if (new.predecessor_cursor_id, new.tenant_id, new.namespace_epoch, new.routing_epoch,
        new.bucket, new.prefix, new.delimiter,
        new.list_version, new.last_key, new.last_common_prefix,
        new.response_state, new.response_state_bytes, new.final_page, new.created_at_ms,
        new.expires_at_ms)
       is distinct from
       (old.predecessor_cursor_id, old.tenant_id, old.namespace_epoch, old.routing_epoch,
        old.bucket, old.prefix, old.delimiter,
        old.list_version, old.last_key, old.last_common_prefix,
        old.response_state, old.response_state_bytes, old.final_page, old.created_at_ms,
        old.expires_at_ms) then
        raise exception 'managed list cursor payload is immutable';
    end if;
    return new;
end;
$$;

drop trigger if exists managed_cursor_payload_immutable
    on managed_list_cursors;
create trigger managed_cursor_payload_immutable
before update on managed_list_cursors
for each row execute function s4_managed_cursor_payload_immutable();
