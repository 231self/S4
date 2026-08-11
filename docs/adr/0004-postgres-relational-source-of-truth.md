# ADR 0004: Postgres Relational Source of Truth

Date: 2026-08-09
Status: Accepted

## Context

S4 needs a control-plane data store for users, workspaces, destinations, policies, API keys, usage records, and audit events. Options:

- **Cloudflare D1**: Global SQLite but limited relational constraints and per-request latency variance.
- **Durable Objects**: Good for stateful coordination but not a relational store.
- **KV/Queues**: Not suitable for relational queries, authorization, or billing integrity.
- **Supabase Postgres**: Full relational model, RLS for multi-tenant isolation, authentication integration.

## Decision

Use Supabase Postgres as the sole relational business data store. No JSONB for application state; only for opaque payloads (Paddle webhooks, signed manifests, audit details). Store money as integer minor units, byte usage as BIGINT.

## Consequences

- RLS enforces workspace isolation; service-role credentials exist only in server-side Worker secrets.
- Migration workflow is expand/contract, backward compatible across one version.
- Avoid D1, Durable Objects, KV, Workflows, and Containers until a demonstrated need exists.
- Database dependency for deployments means the local stack includes Supabase CLI for testing.
