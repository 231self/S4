-- Bound repair retries with exponential backoff and a terminal dead-letter
-- state so a permanently failing repair (e.g. a provider that never returns)
-- cannot retry forever.
alter table managed_object_repairs
    add column if not exists not_before_ms bigint not null default 0,
    drop constraint if exists managed_object_repairs_state_check,
    add constraint managed_object_repairs_state_check
        check (state in ('PENDING', 'WAITING_CUTOVER', 'LEASED', 'DONE', 'DEAD'));
