-- Global, keyset-paginated placement reconciliation scans only live authorities.
create index if not exists managed_object_authorities_placement_page_idx
    on managed_object_authorities (tenant_id, bucket, logical_key, placement_version)
    where tombstone = false;
