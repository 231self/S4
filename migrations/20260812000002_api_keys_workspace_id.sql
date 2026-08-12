-- Scope API keys to workspaces.
alter table api_keys add column if not exists workspace_id uuid
    references workspaces(id) on delete set null;

create index if not exists api_keys_workspace_id_idx on api_keys(workspace_id);
