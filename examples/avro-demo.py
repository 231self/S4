#!/usr/bin/env python3
"""Avro OCF round-trip demo: PUT, raw read, and redacted processed read.

Start a local gateway with binary processing enabled and local auth:

    AUTH_DISABLED=true MASKURA_ENABLE_AVRO=true MASKURA_TRANSFORMED_READ_SPOOL=encrypted \
        cargo run --bin s4-gateway

The gateway prints ``MASKURA_ACCESS_KEY`` / ``MASKURA_SECRET_KEY`` at startup. Export them
and run this script:

    export MASKURA_ACCESS_KEY=... MASKURA_SECRET_KEY=...
    pip install requests fastavro
    python examples/avro-demo.py

The script uploads a small Avro OCF with ``application/avro``, reads the stored
object back (which is a normalized OCF), and reads it again through the typed
processor with ``x-maskura-encrypt-fields: email`` and no bound public key, which
redacts the selected string field.
"""

import io
import os

import requests
from fastavro import reader, writer

GATEWAY = os.environ.get("MASKURA_GATEWAY_URL", "http://127.0.0.1:8080")
ACCESS = os.environ["MASKURA_ACCESS_KEY"]
SECRET = os.environ["MASKURA_SECRET_KEY"]
BUCKET = "avro-demo"
KEY = "customers/day=2026-08-30/part-000.avro"

SCHEMA = {
    "type": "record",
    "name": "Customer",
    "namespace": "maskura.example",
    "fields": [
        {"name": "id", "type": "long"},
        {"name": "email", "type": ["null", "string"]},
    ],
}
RECORDS = [
    {"id": 1, "email": "ada@example.com"},
    {"id": 2, "email": None},
]


def auth() -> dict:
    return {"x-maskura-access-key": ACCESS, "x-maskura-secret-key": SECRET}


def encode_ocf(records: list) -> bytes:
    buffer = io.BytesIO()
    writer(buffer, SCHEMA, records, codec="null")
    return buffer.getvalue()


def decode_ocf(payload: bytes) -> list:
    return list(reader(io.BytesIO(payload)))


def main() -> None:
    put = requests.put(
        f"{GATEWAY}/{BUCKET}/{KEY}",
        headers={**auth(), "Content-Type": "application/avro"},
        data=encode_ocf(RECORDS),
        timeout=60,
    )
    put.raise_for_status()
    print("stored Avro OCF (PUT processed)")

    raw = requests.get(f"{GATEWAY}/{BUCKET}/{KEY}", headers=auth(), timeout=60)
    raw.raise_for_status()
    assert raw.content[:4] == b"Obj\x01", "stored object is not an Avro OCF"
    assert decode_ocf(raw.content) == RECORDS, "raw read must preserve records"
    print("raw GET preserves records")

    processed = requests.get(
        f"{GATEWAY}/{BUCKET}/{KEY}",
        headers={
            **auth(),
            "x-maskura-process": "read",
            "x-maskura-encrypt-fields": "email",
        },
        timeout=60,
    )
    processed.raise_for_status()
    redacted = decode_ocf(processed.content)
    assert redacted[0]["email"] == "[REDACTED]", "email must be redacted"
    assert redacted[1]["email"] is None, "null email must stay null"
    print("processed GET redacts the selected field without leaking plaintext")

    print("PASS: Avro PUT, raw read, and redacted processed read round trip")


if __name__ == "__main__":
    main()
