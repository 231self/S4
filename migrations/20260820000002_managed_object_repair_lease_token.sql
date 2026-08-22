-- A fresh token fences terminal work after an expired lease is reclaimed.
alter table managed_object_repairs
    add column if not exists lease_token uuid;
