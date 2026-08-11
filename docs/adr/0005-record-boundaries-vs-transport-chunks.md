# ADR 0005: Record Boundaries vs Transport Chunks

Date: 2026-08-09
Status: Accepted

## Context

Input streams arrive in arbitrary byte chunks that may split records, UTF-8 code points, CSV fields, or JSON tokens. PII detection applied independently to each transport chunk would miss patterns spanning chunk boundaries.

## Decision

Decouple record boundaries from transport chunks. Format-specific decoders assemble logical records from the byte stream before presenting them to Wasm filters. Record assembly must be UTF-8 code-point safe and handle chunk boundaries across all supported formats (JSONL lines, CSV quoted fields, JSON tokens).

## Consequences

- Every chunk split of the same input must produce identical output and counters. Property tests verify this invariant.
- Decoder state is per-object; no cross-object state.
- Record boundaries for text/JSONL are lines; for CSV, quote-aware line splitting; for JSON, the entire document is one record in MVP.
- Chunk-size invariant property tests are required in CI from Phase 1 onward.
