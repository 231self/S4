-- Placement cleanup is persisted but cannot be claimed until authority CAS has
-- durably installed every required destination.
alter table managed_object_repairs
    drop constraint if exists managed_object_repairs_state_check,
    add constraint managed_object_repairs_state_check
        check (state in ('PENDING', 'WAITING_CUTOVER', 'LEASED', 'DONE'));
