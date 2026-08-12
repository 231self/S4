#!/usr/bin/env python3
"""S4 Python SDK round-trip demo.

1. Generate an RSA-2048 keypair
2. Bind the public key to an API key (gateway stores it)
3. put_object() -> the envelope-encrypt plugin encrypts every PII field
4. get_object()  -> the stored bytes come back unchanged (envelopes)
5. decrypt_payload() -> recover the plaintext with the private key

Requires a running S4 gateway with the envelope-encrypt pipeline enabled.
This script starts one itself (docker image pinned to the s4ctl version) and
switches the pipeline via the dashboard API, so it is self-contained.

Run:
    pip install -r sdks/python/requirements.txt
    python examples/sdk-encrypt-demo.py
"""

import os
import re
import subprocess
import sys
import time

import requests

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "sdks", "python"))

from s4_client import S4Client  # noqa: E402

GATEWAY = os.environ.get("S4_GATEWAY_URL", "http://127.0.0.1:8080")
CONTAINER = "s4-local-gateway"
BUCKET = "sdk-demo"
KEY = "records.txt"
PAYLOAD = b"jane.doe@example.com 4111111111111111\nuser2@test.org 123-45-6789\n"


def sh(*args: str) -> None:
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def wait_health(url: str, tries: int = 30) -> None:
    for _ in range(tries):
        try:
            if requests.get(f"{url}/health", timeout=2).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(1)
    raise SystemExit("gateway did not become healthy")


def main() -> None:
    version = os.environ.get("S4CTL_VERSION")
    if version:
        tag = f"ghcr.io/231self/s4/s4:v{version}"
    else:
        tag = f"ghcr.io/231self/s4/s4:v0.3.3"

    print("=== S4 Python SDK round-trip demo ===")
    sh("docker", "rm", "-f", CONTAINER)
    sh(
        "docker", "run", "-d", "--name", CONTAINER, "-p", "127.0.0.1:8080:8080",
        "-e", "AUTH_DISABLED=true", tag,
    )
    wait_health(GATEWAY)

    print("--- switch pipeline: pii-default OFF, envelope-encrypt ON ---")
    plugins = requests.get(f"{GATEWAY}/dashboard/api/plugins").json()
    pii_id = next(p["id"] for p in plugins if p["name"] == "pii-default")
    requests.put(f"{GATEWAY}/dashboard/api/plugins/{pii_id}", json={"enabled": False})
    component = os.path.join(REPO, "target", "components", "envelope-encrypt.component.wasm")
    requests.post(
        f"{GATEWAY}/dashboard/api/plugins",
        headers={"x-s4-plugin-name": "envelope-encrypt"},
        data=open(component, "rb").read(),
    )

    print("--- SDK flow ---")
    client = S4Client(gateway=GATEWAY)
    pub, priv = client.generate_keypair()
    client.attach_public_key(pub)
    client.put_object(BUCKET, KEY, PAYLOAD)
    blob = client.get_object(BUCKET, KEY)

    assert b"jane.doe@example.com" not in blob, "plaintext leaked"
    assert b"4111111111111111" not in blob, "plaintext card leaked"
    print("stored object contains no plaintext PII (envelopes only):")
    print(f"  {blob[:120].decode(errors='replace')}...")

    decrypted = client.decrypt_payload(blob, priv)
    fields = sorted(set(decrypted.splitlines()))
    print("decrypted fields:")
    for f in fields:
        print(f"  {f}")

    expected = {"jane.doe@example.com", "4111111111111111", "user2@test.org", "123-45-6789"}
    missing = expected - set(fields)
    if missing:
        raise SystemExit(f"FAIL: missing from decrypted: {missing}")
    print(f"PASS: all {len(expected)} PII values recovered by the client")

    sh("docker", "rm", "-f", CONTAINER)


if __name__ == "__main__":
    main()
