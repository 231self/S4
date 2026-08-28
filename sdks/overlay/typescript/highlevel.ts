/**
 * High-level S4 client: object write/read + envelope encrypt/decrypt.
 *
 * The generated low-level client covers the dashboard API (keys, plugins,
 * backends). This module adds the S3 data-plane operations the gateway
 * exposes plus the client side of the envelope-encryption scheme:
 *
 * - `putObject` / `getObject` — raw byte objects through the gateway,
 *   authenticated with the S4 API key headers.
 * - `generateKeypair` — an RSA-2048 keypair (SPKI public key). Give the
 *   public half to S4 and keep the private half locally; S4 never sees it.
 * - `attachPublicKey` — bind the public key to this API key. After this,
 *   the gateway's `envelope-encrypt` plugin encrypts every detected PII
 *   field server-side on PUT.
 * - `decryptPayload` — recover plaintext from a stored payload: scans for
 *   `RSA-OAEP/AES-256-GCM` envelopes, unwraps each DEK with the client-held
 *   private key, and AES-256-GCM-decrypts the field back to plaintext.
 *
 * Write path (server-side encryption):
 *   const client = new S4Client({ endpoint, accessKey, secretKey });
 *   const { privateKeyPem, publicKeyPem } = await S4Client.generateKeypair();
 *   await client.attachPublicKey(publicKeyPem);            // once per key
 *   await client.putObject("my-bucket", "ingest/data.jsonl", payload);
 *
 * Read path (client-side decryption):
 *   const raw = await client.getObject("my-bucket", "ingest/data.jsonl");
 *   const plaintext = await S4Client.decryptPayload(raw, privateKeyPem);
 *
 * Uses only the Web Crypto API and global fetch (browser or Node >= 18).
 */

declare const globalThis: any;

export interface S4ClientOptions {
  endpoint: string;
  accessKey: string;
  secretKey: string;
  timeoutMs?: number;
}

export class S4Client {
  private readonly endpoint: string;
  private readonly accessKey: string;
  private readonly secretKey: string;
  private readonly timeoutMs: number;

  constructor(opts: S4ClientOptions) {
    this.endpoint = opts.endpoint.replace(/\/$/, "");
    this.accessKey = opts.accessKey;
    this.secretKey = opts.secretKey;
    this.timeoutMs = opts.timeoutMs ?? 60_000;
  }

  private authHeaders(): Record<string, string> {
    return { "x-s4-access-key": this.accessKey, "x-s4-secret-key": this.secretKey };
  }

  // -- keys ---------------------------------------------------------

  /** Generate an RSA-2048 keypair for envelope encryption (SPKI/PKCS#8 PEM). */
  static async generateKeypair(): Promise<{ privateKeyPem: string; publicKeyPem: string }> {
    const subtle = globalThis.crypto.subtle;
    const kp = await subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"],
    );
    const spki = await subtle.exportKey("spki", kp.publicKey);
    const pkcs8 = await subtle.exportKey("pkcs8", kp.privateKey);
    return {
      publicKeyPem: S4Client.toPem(spki, "PUBLIC KEY"),
      privateKeyPem: S4Client.toPem(pkcs8, "PRIVATE KEY"),
    };
  }

  /** Bind `publicKeyPem` to this API key so the gateway encrypts PII. */
  async attachPublicKey(publicKeyPem: string): Promise<void> {
    const resp = await fetch(`${this.endpoint}/dashboard/api/keys/public-key`, {
      method: "PUT",
      headers: { ...this.authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ key_id: this.accessKey, public_key_pem: publicKeyPem }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!resp.ok) throw new Error(`attachPublicKey failed: ${resp.status} ${await resp.text()}`);
  }

  // -- object data plane -------------------------------------------

  /** Upload `data` to `bucket/key` through the S4 filter pipeline. */
  async putObject(
    bucket: string,
    key: string,
    data: Uint8Array,
    contentType = "text/plain",
  ): Promise<void> {
    const resp = await fetch(`${this.endpoint}/${bucket}/${key}`, {
      method: "PUT",
      headers: { ...this.authHeaders(), "Content-Type": contentType },
      body: data,
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!resp.ok) throw new Error(`putObject failed: ${resp.status} ${await resp.text()}`);
  }

  /** Download the object stored at `bucket/key` (envelopes included). */
  async getObject(bucket: string, key: string): Promise<Uint8Array> {
    const resp = await fetch(`${this.endpoint}/${bucket}/${key}`, {
      method: "GET",
      headers: this.authHeaders(),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!resp.ok) throw new Error(`getObject failed: ${resp.status} ${await resp.text()}`);
    return new Uint8Array(await resp.arrayBuffer());
  }

  // -- envelope crypto ----------------------------------------------

  /** Decrypt every envelope in `payload` back to plaintext. */
  static async decryptPayload(payload: Uint8Array, privateKeyPem: string): Promise<Uint8Array> {
    const subtle = globalThis.crypto.subtle;
    const privKey = await subtle.importKey(
      "pkcs8",
      S4Client.pemToDer(privateKeyPem),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"],
    );
    const bytes = Array.from(payload);
    const marker = Array.from(new TextEncoder().encode('"alg":"RSA-OAEP/AES-256-GCM"'));
    const out: number[] = [];
    let pos = 0;
    while (true) {
      const idx = S4Client.indexOf(bytes, marker, pos);
      if (idx < 0) {
        for (let i = pos; i < bytes.length; i++) out.push(bytes[i]!);
        break;
      }
      const start = bytes.lastIndexOf(0x7b /* { */, idx);
      if (start < 0) {
        for (let i = pos; i < idx + marker.length; i++) out.push(bytes[i]!);
        pos = idx + marker.length;
        continue;
      }
      let depth = 0;
      let end = -1;
      for (let j = start; j < bytes.length; j++) {
        if (bytes[j] === 0x7b) depth++;
        else if (bytes[j] === 0x7d) {
          depth--;
          if (depth === 0) {
            end = j + 1;
            break;
          }
        }
      }
      if (end < 0) {
        for (let i = pos; i < bytes.length; i++) out.push(bytes[i]!);
        break;
      }
      const env = JSON.parse(new TextDecoder().decode(new Uint8Array(bytes.slice(start, end))));
      const plain = await S4Client.decryptEnvelope(env, privKey);
      for (let i = pos; i < start; i++) out.push(bytes[i]!);
      for (let i = 0; i < plain.length; i++) out.push(plain[i]!);
      pos = end;
    }
    return new Uint8Array(out);
  }

  private static async decryptEnvelope(env: any, privKey: CryptoKey): Promise<number[]> {
    if (env.alg !== "RSA-OAEP/AES-256-GCM") throw new Error(`unsupported alg: ${env.alg}`);
    const subtle = globalThis.crypto.subtle;
    const dek = await subtle.decrypt(
      { name: "RSA-OAEP" },
      privKey,
      S4Client.b64ToBuf(env.enc_dek),
    );
    const iv = S4Client.b64ToBuf(env.iv);
    const ct = new Uint8Array(S4Client.b64ToBuf(env.ct));
    const tag = new Uint8Array(S4Client.b64ToBuf(env.tag));
    const aead = await subtle.importKey("raw", dek, "AES-GCM", false, ["decrypt"]);
    const combined = new Uint8Array(ct.length + tag.length);
    combined.set(ct, 0);
    combined.set(tag, ct.length);
    const pt = await subtle.decrypt({ name: "AES-GCM", iv, tagLength: 128 }, aead, combined);
    return Array.from(new Uint8Array(pt));
  }

  private static toPem(der: ArrayBuffer, label: string): string {
    const bytes = new Uint8Array(der);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
    const b64 = btoa(bin).replace(/(.{64})/g, "$1\n");
    return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
  }

  private static pemToDer(pem: string): ArrayBuffer {
    const b64 = pem.replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "").replace(/\s+/g, "");
    return S4Client.b64ToBuf(b64);
  }

  private static b64ToBuf(b64: string): ArrayBuffer {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }

  private static indexOf(haystack: number[], needle: number[], from: number): number {
    outer: for (let i = from; i <= haystack.length - needle.length; i++) {
      for (let j = 0; j < needle.length; j++) {
        if (haystack[i + j] !== needle[j]) continue outer;
      }
      return i;
    }
    return -1;
  }
}
