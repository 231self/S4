const assert = require("node:assert/strict");
const test = require("node:test");

const { MaskuraClient, S4Client } = require("../dist/highlevel.js");

test("attachPublicKey sends target API key credentials", async () => {
  const originalFetch = global.fetch;
  let request;
  global.fetch = async (url, options) => {
    request = { url, options };
    return { ok: true };
  };

  try {
    const client = new MaskuraClient({
      endpoint: "https://gateway.example/",
      accessKey: "test-access",
      secretKey: "test-secret",
      timeoutMs: 7,
    });
    await client.attachPublicKey("test-public-key");
  } finally {
    global.fetch = originalFetch;
  }

  assert.equal(request.url, "https://gateway.example/dashboard/api/keys/public-key");
  assert.equal(request.options.method, "PUT");
  assert.deepEqual(request.options.headers, {
    "x-maskura-access-key": "test-access",
    "x-maskura-secret-key": "test-secret",
    "Content-Type": "application/json",
  });

  assert.ok(new S4Client({ endpoint: "https://gateway.example", accessKey: "a", secretKey: "s" }) instanceof MaskuraClient);
  assert.deepEqual(JSON.parse(request.options.body), {
    key_id: "test-access",
    public_key_pem: "test-public-key",
  });
});
