# Examples

Runnable end-to-end demos. Credentials always come from the environment —
never committed.

## Local quickstart (`local-quickstart.sh`)

The getting-started flow as a testable script: start the gateway from the
published image (pinned to the `maskura` executable version), push a sample through the
pipeline, assert redaction, stop.

```bash
bash examples/local-quickstart.sh
```

Requires `maskura`
(`cargo install --git https://github.com/231self/S4 --bin maskura s4ctl`)
and Docker.

## B2 demos (`b2-encrypt-demo.sh`, `b2-redact-demo.sh`)

Round-trips against a real Backblaze B2 bucket, fetching the stored object
**directly from B2** (bypassing Maskura) so you can see exactly what leaves your
writer:

- **`b2-encrypt-demo.sh`** — envelope-encryption: pre-encrypt fixture →
  RSA-OAEP/AES-256-GCM envelopes at rest in B2 → client-side decryption.
- **`b2-redact-demo.sh`** — redaction: fixture passes through `pii-default`,
  and the object stored in B2 contains only `[REDACTED_*]` markers.

```bash
export B2_S3_ENDPOINT=https://s3.us-east-005.backblazeb2.com
export B2_REGION=us-east-005
export B2_BUCKET=your-bucket
export B2_ACCESS_KEY_ID=your-key-id
export B2_SECRET_ACCESS_KEY=your-application-key

bash examples/b2-encrypt-demo.sh
bash examples/b2-redact-demo.sh
```

The B2 application key needs `readFiles`/`writeFiles`/`deleteFiles` on the
bucket. The demos use the repo's public fixtures (`tests/fixtures/pii/`) as the
encryption keypair; in production you'd bind your own public key to the API key.

## Python SDK round-trip (`sdk-encrypt-demo.py`)

Keypair → attach public key → `put_object` (gateway encrypts PII server-side) →
`get_object` → `decrypt_payload` with the private key. Starts its own gateway
and switches the pipeline to `envelope-encrypt`.

```bash
pip install -r sdks/python/requirements.txt
python examples/sdk-encrypt-demo.py
```
