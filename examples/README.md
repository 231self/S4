# Examples

## B2 envelope-encryption demo (`b2-encrypt-demo.sh`)

Shows the full encryption round-trip against a real Backblaze B2 bucket:
1. **Pre-encrypt** — the fixture as you have it
2. **Encrypted at rest** — the bytes stored in B2, fetched directly from the
   bucket (bypassing S4), so you can see what actually leaves your writer
3. **Decrypted** — GET through S4 + client-side decryption with the private key

```bash
export B2_S3_ENDPOINT=https://s3.us-east-005.backblazeb2.com
export B2_REGION=us-east-005
export B2_BUCKET=your-bucket
export B2_ACCESS_KEY_ID=your-key-id
export B2_SECRET_ACCESS_KEY=your-application-key
bash examples/b2-encrypt-demo.sh
```

The B2 application key needs `readFiles`/`writeFiles`/`deleteFiles` on the bucket.
The demo uses the repo's public fixtures (`tests/fixtures/pii/crypto/`) as the
encryption keypair; in production you'd bind your own public key to the API key.

## Redaction

`scripts/e2e-local.sh` runs the redaction pipeline against a local MinIO
(no external account needed).
