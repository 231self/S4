# Avro OCF support

Avro Object Container File processing is a typed binary format, intentionally
separate from JSON/CSV text processing: an Avro writer must know the complete
output schema before it emits the first object.

## Enablement

Avro processing is off by default. Operators enable it with
`S4_ENABLE_AVRO=true`. Disabled requests are rejected before the request body is
polled. Raw GET, HEAD, and Range passthrough for stored Avro objects do not
require the gate; only processing (PUT, processed GET, staged multipart
completion) does.

## Supported codec subset

The codec accepts:

- OCF records with `null`, `boolean`, `int`, `long`, `float`, `double`, `bytes`,
  and `string` values.
- Records, arrays, maps with string keys, and exactly nullable unions of the
  form `["null", T]`.
- Logical `date`, `time-millis`, `time-micros`, `timestamp-millis`,
  `timestamp-micros`, `timestamp-nanos`, `uuid`, and `decimal` values.
- Nested combinations of those types, subject to S4 Schema/Value IR limits.

It rejects recursive/named references, arbitrary unions, enums, and fixed
values. Input OCF blocks may use `null`, `deflate`, `snappy`, or `zstandard`;
generated output uses Zstandard with normalized metadata. Source input is capped
before the Avro library reads it, and every emitted value is validated against
the bounded S4 IR schema.

## Processing model

Each processed object follows this order:

```text
Avro OCF -> Schema/Value IR -> BinaryReductor -> BinaryTransform
         -> BinaryReductor restore -> validated Schema/Value IR -> Avro OCF
```

Text `s4:filter` plugins are not inserted in this flow. They receive opaque
bytes and cannot declare an output schema.

## Envelope encryption

`x-s4-encrypt-fields` selects comma-separated string schema paths, for example
`email` or `contacts[*].email`. With an authenticated public key, selected
fields become `RSA-OAEP/AES-256-GCM` envelope records and the Avro schema is
evolved before encoding. Without a public key, selected fields are redacted to
`[REDACTED]` while the string schema is preserved. Overlapping or invalid paths
are rejected. Multipart completion uses identity processing; field selection
applies to single PUT and processed GET.

## Multipart and processed reads

Staged multipart completion concatenates the encrypted parts into one OCF source
and runs it through the same processor rather than treating parts as independent
streams. A processed read (`x-s4-process: read`) runs the source through the
typed pump and stages the complete output in the existing encrypted read spool
before disclosure. Processed read failures never disclose raw source bytes.

## Verify codec work

```bash
cargo test -p s4-gateway avro::tests
cargo test -p s4-gateway binary_pump::tests
```

The suite covers OCF schema/value round trips, nullable/container records,
logical values, decimal precision/scale, source-size boundaries, transport
chunk invariance, unsupported schemas, and processing through a typed
transform.

## Hive-compatible layouts

S4 treats a Hive partition path as an ordinary object key. For example:

```text
warehouse/customers/day=2026-08-30/part-000.avro
```

The Avro schema remains in the OCF header. S4 does not provide a Hive Metastore,
table DDL, SQL query engine, or ORC support.
