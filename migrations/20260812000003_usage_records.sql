-- Per-workspace, per-billing-period usage counters.
-- Aggregated from per-request middleware; reported to Paddle for billing.
create table if not exists usage_records (
    id bigserial primary key,
    workspace_id uuid not null references workspaces(id) on delete cascade,
    period_start timestamptz not null,
    period_end timestamptz not null,
    write_count bigint not null default 0,
    read_count bigint not null default 0,
    gb_processed double precision not null default 0,
    mirror_destinations integer not null default 0,
    created_at timestamptz not null default now(),
    unique (workspace_id, period_start)
);

create index usage_records_workspace_period_idx on usage_records(workspace_id, period_start desc);
