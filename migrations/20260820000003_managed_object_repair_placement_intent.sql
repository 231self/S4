-- Placement repair legs carry the complete requested placement so completion
-- can advance the authority only after all required destinations are ready.
alter table managed_object_repairs
    add column if not exists placement_primary_backend_id text,
    add column if not exists placement_replica_backend_id text;
