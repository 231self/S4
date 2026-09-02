-- BYO operation rows retain only opaque immutable config/attestation identities
-- and routing lease fences. Credential material remains in the private config
-- repository and is loaded by version during recovery.
alter table object_operations
    add column if not exists backend_config_version text,
    add column if not exists capability_attestation_id text,
    add column if not exists routing_epoch bigint check (routing_epoch is null or routing_epoch > 0),
    add column if not exists routing_lease_id uuid,
    add column if not exists routing_fencing_token bigint check (
        routing_fencing_token is null or routing_fencing_token > 0
    ),
    add column if not exists mutation_not_before_ms bigint,
    add column if not exists exact_absence_observed_at_ms bigint;

alter table object_operations
    add constraint object_operations_workspace_binding_complete check (
        (backend_config_version is null
            and capability_attestation_id is null
            and routing_epoch is null
            and routing_lease_id is null
            and routing_fencing_token is null)
        or
        (backend_config_version is not null
            and capability_attestation_id is not null
            and routing_epoch is not null
            and routing_lease_id is not null
            and routing_fencing_token is not null)
    );

create index if not exists object_operations_workspace_recovery_idx
    on object_operations (tenant_id, backend_config_version, state, updated_at_ms)
    where backend_config_version is not null
      and state not in ('COMMITTED', 'PROVEN_ABORTED');
