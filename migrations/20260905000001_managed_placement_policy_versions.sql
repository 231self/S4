-- Durable placement-policy facts. A policy change (backend identity, weight,
-- or capacity) must be accompanied by a version bump. Startup records the
-- policy and rejects a same-version edit before any object is placed against a
-- silently-changed policy.
create table managed_placement_policy_versions (
    version integer primary key,
    fingerprint text not null,
    backend_facts text not null,
    activated_at_ms bigint not null
);
