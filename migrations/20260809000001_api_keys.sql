create table if not exists api_keys (
    id uuid primary key default gen_random_uuid(),
    user_id text not null,
    key_id text not null unique,
    secret_hash text not null,
    label text not null default 'default',
    created_at timestamptz not null default now()
);

create index api_keys_user_id_idx on api_keys(user_id);
create index api_keys_key_id_idx on api_keys(key_id);
