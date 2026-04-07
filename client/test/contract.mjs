/**
 * Contract tests for SimpleVault API.
 * Run against a running server (usually the Rust binary), or use test/run-with-rust-server.mjs.
 *
 * Usage:
 *   SIMPLEVAULT_BASE_URL=http://localhost:8080 node --test test/contract.mjs
 *
 * Default base URL: http://localhost:8080
 */

import { describe, it } from "node:test";
import assert from "node:assert";
import { createHmac } from "node:crypto";
import { createServer } from "node:http";

const BASE_URL = (
  process.env.SIMPLEVAULT_BASE_URL || "http://localhost:8080"
).replace(/\/$/, "");
const API_KEY = process.env.SIMPLEVAULT_API_KEY || "contract-test-key";
const ENABLE_DB_TESTS = process.env.SIMPLEVAULT_ENABLE_DB_TESTS === "1";
const TEST_DB_URL =
  process.env.SIMPLEVAULT_TEST_DB_URL ||
  "postgres://simplevault:simplevault@127.0.0.1:55432/simplevault_test";

async function request(method, path, body = undefined, apiKey = API_KEY) {
  const url = `${BASE_URL}${path}`;
  const options = {
    method,
    headers: { "Content-Type": "application/json", "x-api-key": apiKey },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  };
  const res = await fetch(url, options);
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    // leave data null for non-JSON responses
  }
  return { status: res.status, data, text };
}

describe("SimpleVault API contract", () => {
  describe("GET /v1/:keyName/version", () => {
    it("returns version for existing key", async () => {
      const { status, data } = await request("GET", "/v1/vault/version");
      assert.strictEqual(status, 200, `Expected 200, got ${status}`);
      assert.ok(
        data && typeof data.version === "number",
        `Expected { version: number }, got ${JSON.stringify(data)}`,
      );
      assert.ok(data.version >= 1, "version should be at least 1");
    });

    it("returns 500 for unknown key", async () => {
      const { status, data } = await request("GET", "/v1/nonexistent/version");
      assert.strictEqual(status, 500, `Expected 500, got ${status}`);
      assert.ok(
        data?.error?.includes("key not found") ||
          data?.error?.includes("nonexistent"),
        `Expected key not found error, got ${JSON.stringify(data)}`,
      );
    });
  });

  describe("POST /v1/:keyName/encrypt", () => {
    it("encrypts plaintext and returns ciphertext", async () => {
      const { status, data } = await request("POST", "/v1/vault/encrypt", {
        plaintext: "secret message",
      });
      assert.strictEqual(status, 200, `Expected 200, got ${status}`);
      assert.ok(
        typeof data?.ciphertext === "string",
        `Expected { ciphertext: string }, got ${JSON.stringify(data)}`,
      );
      assert.ok(
        data.ciphertext.startsWith("v"),
        "ciphertext should start with v (version prefix)",
      );
      assert.ok(
        data.ciphertext.includes(":"),
        "ciphertext should be in v{version}:{hex}:{hex} format",
      );
    });

    it("returns 422 for missing plaintext", async () => {
      const { status, data } = await request("POST", "/v1/vault/encrypt", {});
      assert.strictEqual(status, 422, `Expected 422, got ${status}`);
      assert.ok(
        data?.error,
        `Expected error field, got ${JSON.stringify(data)}`,
      );
    });

    it("returns 422 for invalid plaintext (not string)", async () => {
      const { status, data } = await request("POST", "/v1/vault/encrypt", {
        plaintext: 123,
      });
      assert.strictEqual(status, 422, `Expected 422, got ${status}`);
      assert.ok(
        data?.error,
        `Expected error field, got ${JSON.stringify(data)}`,
      );
    });
  });

  describe("POST /v1/:keyName/decrypt", () => {
    it("decrypts ciphertext and returns plaintext", async () => {
      const enc = await request("POST", "/v1/vault/encrypt", {
        plaintext: "roundtrip test",
      });
      assert.strictEqual(enc.status, 200, "encrypt should succeed");
      const { status, data } = await request("POST", "/v1/vault/decrypt", {
        ciphertext: enc.data.ciphertext,
      });
      assert.strictEqual(status, 200, `Expected 200, got ${status}`);
      assert.strictEqual(
        data?.plaintext,
        "roundtrip test",
        `Expected plaintext match, got ${JSON.stringify(data)}`,
      );
    });

    it("returns 422 for invalid ciphertext format", async () => {
      const { status, data } = await request("POST", "/v1/vault/decrypt", {
        ciphertext: "not-valid-format",
      });
      assert.strictEqual(status, 422, `Expected 422, got ${status}`);
      assert.ok(
        data?.error,
        `Expected error field, got ${JSON.stringify(data)}`,
      );
    });

    it("returns 422 for missing ciphertext", async () => {
      const { status, data } = await request("POST", "/v1/vault/decrypt", {});
      assert.strictEqual(status, 422, `Expected 422, got ${status}`);
      assert.ok(
        data?.error,
        `Expected error field, got ${JSON.stringify(data)}`,
      );
    });

    it("returns 500 for key version not found", async () => {
      const { status, data } = await request("POST", "/v1/vault/decrypt", {
        ciphertext: "v99:deadbeef:000000000000000000000000",
      });
      assert.strictEqual(status, 500, `Expected 500, got ${status}`);
      assert.ok(
        data?.error?.includes("key not found") ||
          data?.error?.includes("version"),
        `Expected key not found error, got ${JSON.stringify(data)}`,
      );
    });
  });

  describe("POST /v1/:keyName/rotate", () => {
    it("re-encrypts ciphertext and preserves plaintext", async () => {
      const enc = await request("POST", "/v1/vault/encrypt", {
        plaintext: "data to rotate",
      });
      assert.strictEqual(enc.status, 200, "encrypt should succeed");
      assert.ok(
        enc.data.ciphertext.startsWith("v") &&
          enc.data.ciphertext.includes(":"),
        "ciphertext should be in v{version}:{hex}:{hex} format",
      );

      const rot = await request("POST", "/v1/vault/rotate", {
        ciphertext: enc.data.ciphertext,
      });
      assert.strictEqual(rot.status, 200, `Expected 200, got ${rot.status}`);
      assert.ok(
        typeof rot.data?.ciphertext === "string",
        `Expected { ciphertext: string }, got ${JSON.stringify(rot.data)}`,
      );

      const dec = await request("POST", "/v1/vault/decrypt", {
        ciphertext: rot.data.ciphertext,
      });
      assert.strictEqual(dec.status, 200, "decrypt should succeed");
      assert.strictEqual(
        dec.data?.plaintext,
        "data to rotate",
        "rotated ciphertext should decrypt to original",
      );
    });

    it("returns 422 for invalid ciphertext format", async () => {
      const { status, data } = await request("POST", "/v1/vault/rotate", {
        ciphertext: "invalid",
      });
      assert.strictEqual(status, 422, `Expected 422, got ${status}`);
      assert.ok(
        data?.error,
        `Expected error field, got ${JSON.stringify(data)}`,
      );
    });
  });

  describe("POST /v1/:keyName/verify-signature", () => {
    it("verifies hmac-sha256 signature with encrypted secret", async () => {
      const secret = "whsec_test_secret";
      const encSecret = await request("POST", "/v1/vault/encrypt", {
        plaintext: secret,
      });
      assert.strictEqual(
        encSecret.status,
        200,
        "encrypt secret should succeed",
      );
      assert.ok(
        typeof encSecret.data?.ciphertext === "string",
        "encrypt should return ciphertext",
      );

      const payload = '{"id":"evt_test"}';
      const payloadHex = Buffer.from(payload, "utf8").toString("hex");
      const signatureHex = createHmac("sha256", secret)
        .update(payload, "utf8")
        .digest("hex");

      const { status, data } = await request(
        "POST",
        "/v1/vault/verify-signature",
        {
          ciphertext: encSecret.data.ciphertext,
          payload: payloadHex,
          signature: signatureHex,
          algorithm: "hmac-sha256",
        },
      );

      assert.strictEqual(status, 200, `Expected 200, got ${status}`);
      assert.strictEqual(
        data?.verified,
        true,
        `Expected verified=true, got ${JSON.stringify(data)}`,
      );
    });

    it("returns verified=false for signature mismatch", async () => {
      const secret = "whsec_test_secret";
      const encSecret = await request("POST", "/v1/vault/encrypt", {
        plaintext: secret,
      });
      assert.strictEqual(
        encSecret.status,
        200,
        "encrypt secret should succeed",
      );

      const payloadHex = Buffer.from("payload", "utf8").toString("hex");
      const wrongSignatureHex = createHmac("sha256", "wrong_secret")
        .update("payload", "utf8")
        .digest("hex");

      const { status, data } = await request(
        "POST",
        "/v1/vault/verify-signature",
        {
          ciphertext: encSecret.data.ciphertext,
          payload: payloadHex,
          signature: wrongSignatureHex,
          algorithm: "sha256",
        },
      );

      assert.strictEqual(status, 200, `Expected 200, got ${status}`);
      assert.strictEqual(
        data?.verified,
        false,
        `Expected verified=false, got ${JSON.stringify(data)}`,
      );
    });

    it("returns 422 for non-hex payload", async () => {
      const secret = "whsec_test_secret";
      const encSecret = await request("POST", "/v1/vault/encrypt", {
        plaintext: secret,
      });
      assert.strictEqual(
        encSecret.status,
        200,
        "encrypt secret should succeed",
      );

      const { status, data } = await request(
        "POST",
        "/v1/vault/verify-signature",
        {
          ciphertext: encSecret.data.ciphertext,
          payload: "not-hex",
          signature: "abcd",
          algorithm: "hmac-sha256",
        },
      );

      assert.strictEqual(status, 422, `Expected 422, got ${status}`);
      assert.ok(
        data?.error,
        `Expected error field, got ${JSON.stringify(data)}`,
      );
    });

    it("returns 422 for non-hex signature", async () => {
      const secret = "whsec_test_secret";
      const encSecret = await request("POST", "/v1/vault/encrypt", {
        plaintext: secret,
      });
      assert.strictEqual(
        encSecret.status,
        200,
        "encrypt secret should succeed",
      );

      const payloadHex = Buffer.from("payload", "utf8").toString("hex");
      const { status, data } = await request(
        "POST",
        "/v1/vault/verify-signature",
        {
          ciphertext: encSecret.data.ciphertext,
          payload: payloadHex,
          signature: "base64_like+/",
          algorithm: "hmac-sha256",
        },
      );

      assert.ok(
        status === 422 || status === 500,
        `Expected 422 or 500, got ${status}`,
      );
      assert.ok(
        data?.error,
        `Expected error field, got ${JSON.stringify(data)}`,
      );
    });
  });

  describe("POST /v1/:keyName/create-signature", () => {
    it("creates hmac-sha256 signature with encrypted secret", async () => {
      const secret = "whsec_test_secret";
      const encSecret = await request("POST", "/v1/vault/encrypt", {
        plaintext: secret,
      });
      assert.strictEqual(
        encSecret.status,
        200,
        "encrypt secret should succeed",
      );
      assert.ok(
        typeof encSecret.data?.ciphertext === "string",
        "encrypt should return ciphertext",
      );

      const payload = '{"id":"evt_test"}';
      const payloadHex = Buffer.from(payload, "utf8").toString("hex");
      const expectedSignatureHex = createHmac("sha256", secret)
        .update(payload, "utf8")
        .digest("hex");

      const { status, data } = await request(
        "POST",
        "/v1/vault/create-signature",
        {
          ciphertext: encSecret.data.ciphertext,
          payload: payloadHex,
          algorithm: "hmac-sha256",
        },
      );

      assert.strictEqual(status, 200, `Expected 200, got ${status}`);
      assert.strictEqual(
        data?.signature,
        expectedSignatureHex,
        `Expected deterministic signature, got ${JSON.stringify(data)}`,
      );
    });

    it("returns 422 for non-hex payload", async () => {
      const secret = "whsec_test_secret";
      const encSecret = await request("POST", "/v1/vault/encrypt", {
        plaintext: secret,
      });
      assert.strictEqual(
        encSecret.status,
        200,
        "encrypt secret should succeed",
      );

      const { status, data } = await request(
        "POST",
        "/v1/vault/create-signature",
        {
          ciphertext: encSecret.data.ciphertext,
          payload: "not-hex",
          algorithm: "hmac-sha256",
        },
      );

      assert.strictEqual(status, 422, `Expected 422, got ${status}`);
      assert.ok(
        data?.error,
        `Expected error field, got ${JSON.stringify(data)}`,
      );
    });

    it("returns 500 for unsupported algorithm", async () => {
      const secret = "whsec_test_secret";
      const encSecret = await request("POST", "/v1/vault/encrypt", {
        plaintext: secret,
      });
      assert.strictEqual(
        encSecret.status,
        200,
        "encrypt secret should succeed",
      );

      const payloadHex = Buffer.from("payload", "utf8").toString("hex");
      const { status, data } = await request(
        "POST",
        "/v1/vault/create-signature",
        {
          ciphertext: encSecret.data.ciphertext,
          payload: payloadHex,
          algorithm: "rsa-sha256",
        },
      );

      assert.strictEqual(status, 500, `Expected 500, got ${status}`);
      assert.ok(
        data?.error,
        `Expected error field, got ${JSON.stringify(data)}`,
      );
    });
  });

  describe("routing", () => {
    it("returns 404 for unknown path", async () => {
      const { status } = await request("GET", "/v1/vault/unknown");
      assert.strictEqual(status, 404, `Expected 404, got ${status}`);
    });

    it("version does not accept POST", async () => {
      const { status } = await request("POST", "/v1/vault/version", {});
      assert.ok(
        status === 404 || status === 405,
        `Expected 404 or 405, got ${status}`,
      );
    });
  });

  describe("POST /v1/:keyName/proxy-substitute", () => {
    it("substitutes plaintext and proxies response", async () => {
      const upstream = await startUpstreamServer();
      try {
        const encrypted = await request("POST", "/v1/vault/encrypt", {
          plaintext: "token_123",
        });
        assert.strictEqual(encrypted.status, 200, "encrypt should succeed");

        const result = await request("POST", "/v1/vault/proxy-substitute", {
          ciphertext: encrypted.data.ciphertext,
          request: {
            method: "POST",
            url: `${upstream.baseUrl}/echo?auth={{SIMPLEVAULT_PLAINTEXT}}`,
            headers: {
              authorization: "Bearer {{SIMPLEVAULT_PLAINTEXT}}",
              "content-type": "application/json",
            },
            body: '{"token":"{{SIMPLEVAULT_PLAINTEXT}}"}',
          },
        });

        assert.strictEqual(
          result.status,
          200,
          `Expected 200, got ${result.status}`,
        );
        assert.strictEqual(
          result.data?.status,
          200,
          `Expected proxied status 200, got ${JSON.stringify(result.data)}`,
        );
        const upstreamBody = JSON.parse(result.data.body);
        assert.strictEqual(upstreamBody.query.auth, "token_123");
        assert.strictEqual(
          upstreamBody.headers.authorization,
          "Bearer token_123",
        );
        assert.strictEqual(upstreamBody.body.token, "token_123");
      } finally {
        await upstream.stop();
      }
    });

    it("returns 403 when destination is not allowed", async () => {
      const encrypted = await request("POST", "/v1/vault/encrypt", {
        plaintext: "token_123",
      });
      assert.strictEqual(encrypted.status, 200, "encrypt should succeed");

      const result = await request("POST", "/v1/vault/proxy-substitute", {
        ciphertext: encrypted.data.ciphertext,
        request: {
          method: "GET",
          url: "https://example.com/anything",
        },
      });
      assert.strictEqual(
        result.status,
        403,
        `Expected 403, got ${result.status}`,
      );
      assert.ok(result.data?.error?.includes("destination is not allowed"));
    });

    it("returns 403 for localhost HTTP on non-default port when outbound rule omits port", async () => {
      const upstream = await startUpstreamServer();
      try {
        const enc = await request("POST", "/v1/strictlocal/encrypt", {
          plaintext: "p",
        });
        assert.strictEqual(enc.status, 200, "encrypt strictlocal should succeed");
        const result = await request("POST", "/v1/strictlocal/proxy-substitute", {
          ciphertext: enc.data.ciphertext,
          request: {
            method: "GET",
            url: `${upstream.baseUrl}/echo`,
          },
        });
        assert.strictEqual(
          result.status,
          403,
          `Expected 403 for ephemeral port without port allowlist, got ${result.status}`,
        );
        assert.ok(result.data?.error?.includes("destination is not allowed"));
      } finally {
        await upstream.stop();
      }
    });

    it("returns 200 for localhost HTTP on non-default port when outbound rule has port *", async () => {
      const upstream = await startUpstreamServer();
      try {
        const enc = await request("POST", "/v1/wildlocal/encrypt", {
          plaintext: "p",
        });
        assert.strictEqual(enc.status, 200, "encrypt wildlocal should succeed");
        const result = await request("POST", "/v1/wildlocal/proxy-substitute", {
          ciphertext: enc.data.ciphertext,
          request: {
            method: "GET",
            url: `${upstream.baseUrl}/echo`,
          },
        });
        assert.strictEqual(
          result.status,
          200,
          `Expected 200 with port *, got ${result.status}`,
        );
        assert.strictEqual(result.data?.status, 200);
      } finally {
        await upstream.stop();
      }
    });

    it("returns 403 when destination rules are empty for key set", async () => {
      const encrypted = await request("POST", "/v1/blocked/encrypt", {
        plaintext: "token_123",
      });
      assert.strictEqual(encrypted.status, 200, "encrypt should succeed");

      const result = await request("POST", "/v1/blocked/proxy-substitute", {
        ciphertext: encrypted.data.ciphertext,
        request: {
          method: "GET",
          url: "https://example.com/anything",
        },
      });
      assert.strictEqual(
        result.status,
        403,
        `Expected 403, got ${result.status}`,
      );
      assert.ok(result.data?.error?.includes("destination is not allowed"));
    });

    it("returns 403 without proxy operation scope", async () => {
      const encrypted = await request(
        "POST",
        "/v1/limited/encrypt",
        { plaintext: "token_123" },
        "limited-contract-key",
      );
      assert.strictEqual(encrypted.status, 200, "encrypt should succeed");
      const result = await request(
        "POST",
        "/v1/limited/proxy-substitute",
        {
          ciphertext: encrypted.data.ciphertext,
          request: {
            method: "GET",
            url: "http://localhost/echo",
          },
        },
        "limited-contract-key",
      );
      assert.strictEqual(
        result.status,
        403,
        `Expected 403, got ${result.status}`,
      );
      assert.ok(result.data?.error?.includes("not allowed for this operation"));
    });

    it("returns 422 for malformed request payload", async () => {
      const result = await request("POST", "/v1/vault/proxy-substitute", {
        ciphertext: "v1:abcd:abcd",
        request: {
          method: 123,
          url: null,
        },
      });
      assert.strictEqual(
        result.status,
        422,
        `Expected 422, got ${result.status}`,
      );
      assert.ok(result.data?.error);
    });
  });

  describe("POST /v1/:keyName/db-query", () => {
    it("executes query against postgres when DB tests enabled", async () => {
      if (!ENABLE_DB_TESTS) {
        return;
      }

      const encrypted = await request("POST", "/v1/vault/encrypt", {
        plaintext: TEST_DB_URL,
      });
      assert.strictEqual(encrypted.status, 200, "encrypt should succeed");

      const result = await request("POST", "/v1/vault/db-query", {
        ciphertext: encrypted.data.ciphertext,
        query: {
          sql: "select $1::int as n, $2::text as t",
          params: [
            { type: "int4", value: 7 },
            { type: "text", value: "ok" },
          ],
        },
        options: {
          timeout_ms: 3000,
          max_rows: 100,
        },
      });
      assert.strictEqual(
        result.status,
        200,
        `Expected 200, got ${result.status}`,
      );
      assert.strictEqual(result.data?.row_count, 1);
      assert.strictEqual(result.data?.rows?.[0]?.[0], 7);
      assert.strictEqual(result.data?.rows?.[0]?.[1], "ok");
    });

    it("binds typed null parameters for any column type when DB tests enabled", async () => {
      if (!ENABLE_DB_TESTS) {
        return;
      }

      const encrypted = await request("POST", "/v1/vault/encrypt", {
        plaintext: TEST_DB_URL,
      });
      assert.strictEqual(encrypted.status, 200, "encrypt should succeed");

      const result = await request("POST", "/v1/vault/db-query", {
        ciphertext: encrypted.data.ciphertext,
        query: {
          sql: "select ($1::int) is null as n_null, ($2::text) is null as t_null, $3::int as present",
          params: [
            { type: "null", value: null },
            { type: "null", value: null },
            { type: "int4", value: 5 },
          ],
        },
        options: {
          timeout_ms: 3000,
          max_rows: 100,
        },
      });
      assert.strictEqual(
        result.status,
        200,
        `Expected 200, got ${result.status}: ${result.text}`,
      );
      assert.strictEqual(result.data?.row_count, 1);
      assert.strictEqual(result.data?.rows?.[0]?.[0], true);
      assert.strictEqual(result.data?.rows?.[0]?.[1], true);
      assert.strictEqual(result.data?.rows?.[0]?.[2], 5);
    });

    it("inserts null into nullable columns via bound parameters when DB tests enabled", async () => {
      if (!ENABLE_DB_TESTS) {
        return;
      }

      const encrypted = await request("POST", "/v1/vault/encrypt", {
        plaintext: TEST_DB_URL,
      });
      assert.strictEqual(encrypted.status, 200, "encrypt should succeed");

      const tableName = `svnb_${Date.now()}_${Math.floor(Math.random() * 1_000_000)}`;

      const create = await request("POST", "/v1/vault/db-query", {
        ciphertext: encrypted.data.ciphertext,
        query: {
          sql: `create table ${tableName} (id int primary key, n int null, t text null)`,
        },
        options: { timeout_ms: 3000, max_rows: 100 },
      });
      assert.strictEqual(
        create.status,
        200,
        `create table: ${create.status} ${create.text}`,
      );

      const insertNulls = await request("POST", "/v1/vault/db-query", {
        ciphertext: encrypted.data.ciphertext,
        query: {
          sql: `insert into ${tableName} (id, n, t) values (1, $1, $2)`,
          params: [
            { type: "null", value: null },
            { type: "null", value: null },
          ],
        },
        options: { timeout_ms: 3000, max_rows: 100 },
      });
      assert.strictEqual(
        insertNulls.status,
        200,
        `insert nulls: ${insertNulls.status} ${insertNulls.text}`,
      );

      const select1 = await request("POST", "/v1/vault/db-query", {
        ciphertext: encrypted.data.ciphertext,
        query: { sql: `select n, t from ${tableName} where id = 1` },
        options: { timeout_ms: 3000, max_rows: 100 },
      });
      assert.strictEqual(select1.status, 200, select1.text);
      assert.strictEqual(select1.data?.row_count, 1);
      assert.strictEqual(select1.data?.rows?.[0]?.[0], null);
      assert.strictEqual(select1.data?.rows?.[0]?.[1], null);

      const insertMixed = await request("POST", "/v1/vault/db-query", {
        ciphertext: encrypted.data.ciphertext,
        query: {
          sql: `insert into ${tableName} (id, n, t) values (2, $1, $2)`,
          params: [
            { type: "int4", value: 42 },
            { type: "null", value: null },
          ],
        },
        options: { timeout_ms: 3000, max_rows: 100 },
      });
      assert.strictEqual(insertMixed.status, 200, insertMixed.text);

      const select2 = await request("POST", "/v1/vault/db-query", {
        ciphertext: encrypted.data.ciphertext,
        query: { sql: `select n, t from ${tableName} where id = 2` },
        options: { timeout_ms: 3000, max_rows: 100 },
      });
      assert.strictEqual(select2.status, 200, select2.text);
      assert.strictEqual(select2.data?.rows?.[0]?.[0], 42);
      assert.strictEqual(select2.data?.rows?.[0]?.[1], null);

      const drop = await request("POST", "/v1/vault/db-query", {
        ciphertext: encrypted.data.ciphertext,
        query: { sql: `drop table ${tableName}` },
        options: { timeout_ms: 3000, max_rows: 100 },
      });
      assert.strictEqual(drop.status, 200, drop.text);
    });

    it("returns 403 when DB destination is not allowed", async () => {
      const encrypted = await request("POST", "/v1/vault/encrypt", {
        plaintext: "postgres://user:pass@db-not-allowed.internal:5432/app",
      });
      assert.strictEqual(encrypted.status, 200, "encrypt should succeed");

      const result = await request("POST", "/v1/vault/db-query", {
        ciphertext: encrypted.data.ciphertext,
        query: { sql: "select 1" },
      });
      assert.strictEqual(
        result.status,
        403,
        `Expected 403, got ${result.status}`,
      );
      assert.ok(
        result.data?.error?.includes("database destination is not allowed"),
      );
    });

    it("returns 403 without db_query operation scope", async () => {
      const encrypted = await request(
        "POST",
        "/v1/limited/encrypt",
        { plaintext: "postgres://user:pass@127.0.0.1:5432/app" },
        "limited-contract-key",
      );
      assert.strictEqual(encrypted.status, 200, "encrypt should succeed");

      const result = await request(
        "POST",
        "/v1/limited/db-query",
        {
          ciphertext: encrypted.data.ciphertext,
          query: { sql: "select 1" },
        },
        "limited-contract-key",
      );
      assert.strictEqual(
        result.status,
        403,
        `Expected 403, got ${result.status}`,
      );
      assert.ok(result.data?.error?.includes("not allowed for this operation"));
    });

    it("allows read queries for read-only DB destination rules when DB tests enabled", async () => {
      if (!ENABLE_DB_TESTS) {
        return;
      }

      const encrypted = await request(
        "POST",
        "/v1/readonly/encrypt",
        { plaintext: TEST_DB_URL },
        "readonly-contract-key",
      );
      assert.strictEqual(encrypted.status, 200, "encrypt should succeed");

      const result = await request(
        "POST",
        "/v1/readonly/db-query",
        {
          ciphertext: encrypted.data.ciphertext,
          query: { sql: "select 1 as n" },
        },
        "readonly-contract-key",
      );
      assert.strictEqual(
        result.status,
        200,
        `Expected 200, got ${result.status}`,
      );
      assert.strictEqual(result.data?.row_count, 1);
      assert.strictEqual(result.data?.rows?.[0]?.[0], 1);
    });

    it("rejects write queries for read-only DB destination rules when DB tests enabled", async () => {
      if (!ENABLE_DB_TESTS) {
        return;
      }

      const encrypted = await request(
        "POST",
        "/v1/readonly/encrypt",
        { plaintext: TEST_DB_URL },
        "readonly-contract-key",
      );
      assert.strictEqual(encrypted.status, 200, "encrypt should succeed");

      const tableName = `simplevault_contract_readonly_${Date.now()}_${Math.floor(Math.random() * 1_000_000)}`;
      const result = await request(
        "POST",
        "/v1/readonly/db-query",
        {
          ciphertext: encrypted.data.ciphertext,
          query: { sql: `create table ${tableName} (id int primary key)` },
        },
        "readonly-contract-key",
      );
      assert.strictEqual(
        result.status,
        403,
        `Expected 403, got ${result.status}`,
      );
      assert.ok(
        result.data?.error?.includes("query type"),
        `Expected read-only db destination error, got ${JSON.stringify(result.data)}`,
      );
    });

    it("rejects writable CTE queries for read-only DB destination rules when DB tests enabled", async () => {
      if (!ENABLE_DB_TESTS) {
        return;
      }

      const encrypted = await request(
        "POST",
        "/v1/readonly/encrypt",
        { plaintext: TEST_DB_URL },
        "readonly-contract-key",
      );
      assert.strictEqual(encrypted.status, 200, "encrypt should succeed");

      const result = await request(
        "POST",
        "/v1/readonly/db-query",
        {
          ciphertext: encrypted.data.ciphertext,
          query: {
            sql: "with deleted as (delete from pg_type where false returning oid) select count(*) from deleted",
          },
        },
        "readonly-contract-key",
      );
      assert.strictEqual(
        result.status,
        403,
        `Expected 403, got ${result.status}`,
      );
      assert.ok(
        result.data?.error?.includes("query type"),
        `Expected read-only db destination error, got ${JSON.stringify(result.data)}`,
      );
    });

    it("returns descriptive SQL errors when DB tests enabled", async () => {
      if (!ENABLE_DB_TESTS) {
        return;
      }

      const encrypted = await request("POST", "/v1/vault/encrypt", {
        plaintext: TEST_DB_URL,
      });
      assert.strictEqual(encrypted.status, 200, "encrypt should succeed");

      const result = await request("POST", "/v1/vault/db-query", {
        ciphertext: encrypted.data.ciphertext,
        query: {
          sql: "select missing_column from (select 1 as n) t",
        },
      });
      assert.strictEqual(
        result.status,
        422,
        `Expected 422, got ${result.status}`,
      );
      assert.ok(
        typeof result.data?.error === "string",
        `Expected error string, got ${JSON.stringify(result.data)}`,
      );
      assert.ok(
        result.data.error.includes("database error ["),
        `Expected SQLSTATE/code in error message, got ${result.data.error}`,
      );
      assert.ok(
        result.data.error.toLowerCase().includes("missing_column") ||
          result.data.error.toLowerCase().includes("column"),
        `Expected column context in error message, got ${result.data.error}`,
      );
    });

    it("supports typed jsonb and varchar params when DB tests enabled", async () => {
      if (!ENABLE_DB_TESTS) {
        return;
      }

      const encrypted = await request("POST", "/v1/vault/encrypt", {
        plaintext: TEST_DB_URL,
      });
      assert.strictEqual(encrypted.status, 200, "encrypt should succeed");

      const result = await request("POST", "/v1/vault/db-query", {
        ciphertext: encrypted.data.ciphertext,
        query: {
          sql: "select $1::jsonb->>'kind' as kind, $2::varchar as label",
          params: [
            { type: "jsonb", value: { kind: "customer" } },
            { type: "varchar", value: "gold" },
          ],
        },
      });

      assert.strictEqual(
        result.status,
        200,
        `Expected 200, got ${result.status}`,
      );
      assert.strictEqual(result.data?.row_count, 1);
      assert.strictEqual(result.data?.rows?.[0]?.[0], "customer");
      assert.strictEqual(result.data?.rows?.[0]?.[1], "gold");
    });

    it("supports typed timestamptz params when DB tests enabled", async () => {
      if (!ENABLE_DB_TESTS) {
        return;
      }

      const encrypted = await request("POST", "/v1/vault/encrypt", {
        plaintext: TEST_DB_URL,
      });
      assert.strictEqual(encrypted.status, 200, "encrypt should succeed");

      const result = await request("POST", "/v1/vault/db-query", {
        ciphertext: encrypted.data.ciphertext,
        query: {
          sql: "select ($1::timestamptz at time zone 'UTC')::text as ts",
          params: [
            { type: "timestamptz", value: "2025-01-02T03:04:05+00:00" },
          ],
        },
      });

      assert.strictEqual(
        result.status,
        200,
        `Expected 200, got ${result.status}`,
      );
      assert.strictEqual(result.data?.row_count, 1);
      assert.ok(
        String(result.data?.rows?.[0]?.[0] ?? "").startsWith(
          "2025-01-02 03:04:05",
        ),
        `Expected timestamp text, got ${JSON.stringify(result.data)}`,
      );
    });

    it("supports typed json object and array params when DB tests enabled", async () => {
      if (!ENABLE_DB_TESTS) {
        return;
      }

      const encrypted = await request("POST", "/v1/vault/encrypt", {
        plaintext: TEST_DB_URL,
      });
      assert.strictEqual(encrypted.status, 200, "encrypt should succeed");

      const result = await request("POST", "/v1/vault/db-query", {
        ciphertext: encrypted.data.ciphertext,
        query: {
          sql: "select $1::jsonb->>'kind' as kind, jsonb_array_length($2::jsonb) as n",
          params: [
            { type: "jsonb", value: { kind: "customer" } },
            { type: "jsonb", value: [1, 2, 3] },
          ],
        },
      });

      assert.strictEqual(
        result.status,
        200,
        `Expected 200, got ${result.status}`,
      );
      assert.strictEqual(result.data?.row_count, 1);
      assert.strictEqual(result.data?.rows?.[0]?.[0], "customer");
      assert.strictEqual(result.data?.rows?.[0]?.[1], 3);
    });

    it("preserves select column order when DB tests enabled", async () => {
      if (!ENABLE_DB_TESTS) {
        return;
      }

      const encrypted = await request("POST", "/v1/vault/encrypt", {
        plaintext: TEST_DB_URL,
      });
      assert.strictEqual(encrypted.status, 200, "encrypt should succeed");

      const result = await request("POST", "/v1/vault/db-query", {
        ciphertext: encrypted.data.ciphertext,
        query: {
          sql: "select 1 as z, 2 as a, 3 as m",
        },
      });

      assert.strictEqual(
        result.status,
        200,
        `Expected 200, got ${result.status}`,
      );
      assert.strictEqual(result.data?.columns?.[0]?.name, "z");
      assert.strictEqual(result.data?.columns?.[1]?.name, "a");
      assert.strictEqual(result.data?.columns?.[2]?.name, "m");
      assert.strictEqual(result.data?.rows?.[0]?.[0], 1);
      assert.strictEqual(result.data?.rows?.[0]?.[1], 2);
      assert.strictEqual(result.data?.rows?.[0]?.[2], 3);
    });

    it("creates a table and writes rows when DB tests enabled", async () => {
      if (!ENABLE_DB_TESTS) {
        return;
      }

      const encrypted = await request("POST", "/v1/vault/encrypt", {
        plaintext: TEST_DB_URL,
      });
      assert.strictEqual(encrypted.status, 200, "encrypt should succeed");

      const tableName = `simplevault_contract_write_${Date.now()}_${Math.floor(Math.random() * 1_000_000)}`;

      const createResult = await request("POST", "/v1/vault/db-query", {
        ciphertext: encrypted.data.ciphertext,
        query: {
          sql: `create table ${tableName} (id int primary key, label text not null)`,
        },
        options: {
          timeout_ms: 3000,
          max_rows: 100,
        },
      });
      assert.strictEqual(
        createResult.status,
        200,
        `Expected table creation to succeed, got ${createResult.status} with body ${JSON.stringify(createResult.data)}`,
      );

      const insertResult = await request("POST", "/v1/vault/db-query", {
        ciphertext: encrypted.data.ciphertext,
        query: {
          sql: `insert into ${tableName} (id, label) values ($1::int, $2::text), ($3::int, $4::text)`,
          params: [
            { type: "int4", value: 1 },
            { type: "text", value: "first" },
            { type: "int4", value: 2 },
            { type: "text", value: "second" },
          ],
        },
        options: {
          timeout_ms: 3000,
          max_rows: 100,
        },
      });
      assert.strictEqual(
        insertResult.status,
        200,
        `Expected insert to succeed, got ${insertResult.status} with body ${JSON.stringify(insertResult.data)}`,
      );
      assert.strictEqual(insertResult.data?.row_count, 2);
      assert.strictEqual(insertResult.data?.truncated, false);

      const selectResult = await request("POST", "/v1/vault/db-query", {
        ciphertext: encrypted.data.ciphertext,
        query: {
          sql: `select id, label from ${tableName} order by id asc`,
        },
        options: {
          timeout_ms: 3000,
          max_rows: 100,
        },
      });
      assert.strictEqual(
        selectResult.status,
        200,
        `Expected select to succeed, got ${selectResult.status} with body ${JSON.stringify(selectResult.data)}`,
      );
      assert.strictEqual(selectResult.data?.row_count, 2);
      assert.strictEqual(selectResult.data?.rows?.[0]?.[0], 1);
      assert.strictEqual(selectResult.data?.rows?.[0]?.[1], "first");
      assert.strictEqual(selectResult.data?.rows?.[1]?.[0], 2);
      assert.strictEqual(selectResult.data?.rows?.[1]?.[1], "second");

      await request("POST", "/v1/vault/db-query", {
        ciphertext: encrypted.data.ciphertext,
        query: {
          sql: `drop table ${tableName}`,
        },
        options: {
          timeout_ms: 3000,
          max_rows: 100,
        },
      });
    });
  });
});

async function startUpstreamServer() {
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    const body = Buffer.concat(chunks).toString("utf8");
    const parsedBody = body ? JSON.parse(body) : null;
    const urlObject = new URL(req.url || "/", "http://localhost");
    res.setHeader("content-type", "application/json");
    res.end(
      JSON.stringify({
        method: req.method,
        query: Object.fromEntries(urlObject.searchParams.entries()),
        headers: req.headers,
        body: parsedBody,
      }),
    );
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Failed to start upstream test server");
  }
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    stop: () =>
      new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
