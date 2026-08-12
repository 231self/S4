-- Workspaces: multi-tenant organization unit.
-- A workspace groups API keys, usage records, and members.
create table if not exists workspaces (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    slug text not null unique,
    created_at timestamptz not null default now()
);

-- Members with roles.
-- Roles: owner (full control), admin (manage keys + members), member (use keys)
create table if not exists workspace_members (
    workspace_id uuid not null references workspaces(id) on delete cascade,
    user_id text not null,
    role text not null default 'member' check (role in ('owner', 'admin', 'member')),
    joined_at timestamptz not null default now(),
    primary key (workspace_id, user_id)
);

create index workspace_members_user_id_idx on workspace_members(user_id);
