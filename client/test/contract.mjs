/**
 * Contract tests for SimpleVault API.
 * Run against dev server or Rust production server to verify behavior matches.
 *
 * Usage:
 *   SIMPLEVAULT_BASE_URL=http://localhost:8080 node --test test/contract.mjs
 *
 * Default base URL: http://localhost:8080
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';

const BASE_URL = (process.env.SIMPLEVAULT_BASE_URL || 'http://localhost:8080').replace(/\/$/, '');

async function request(method, path, body = undefined) {
  const url = `${BASE_URL}${path}`;
  const options = {
    method,
    headers: { 'Content-Type': 'application/json' },
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

describe('SimpleVault API contract', () => {
  describe('GET /v1/:keyName/version', () => {
    it('returns version for existing key', async () => {
      const { status, data } = await request('GET', '/v1/vault/version');
      assert.strictEqual(status, 200, `Expected 200, got ${status}`);
      assert.ok(data && typeof data.version === 'number', `Expected { version: number }, got ${JSON.stringify(data)}`);
      assert.ok(data.version >= 1, 'version should be at least 1');
    });

    it('returns 500 for unknown key', async () => {
      const { status, data } = await request('GET', '/v1/nonexistent/version');
      assert.strictEqual(status, 500, `Expected 500, got ${status}`);
      assert.ok(data?.error?.includes('key not found') || data?.error?.includes('nonexistent'), `Expected key not found error, got ${JSON.stringify(data)}`);
    });
  });

  describe('POST /v1/:keyName/encrypt', () => {
    it('encrypts plaintext and returns ciphertext', async () => {
      const { status, data } = await request('POST', '/v1/vault/encrypt', { plaintext: 'secret message' });
      assert.strictEqual(status, 200, `Expected 200, got ${status}`);
      assert.ok(typeof data?.ciphertext === 'string', `Expected { ciphertext: string }, got ${JSON.stringify(data)}`);
      assert.ok(data.ciphertext.startsWith('v'), 'ciphertext should start with v (version prefix)');
      assert.ok(data.ciphertext.includes(':'), 'ciphertext should be in v{version}:{hex}:{hex} format');
    });

    it('returns 422 for missing plaintext', async () => {
      const { status, data } = await request('POST', '/v1/vault/encrypt', {});
      assert.strictEqual(status, 422, `Expected 422, got ${status}`);
      assert.ok(data?.error, `Expected error field, got ${JSON.stringify(data)}`);
    });

    it('returns 422 for invalid plaintext (not string)', async () => {
      const { status, data } = await request('POST', '/v1/vault/encrypt', { plaintext: 123 });
      assert.strictEqual(status, 422, `Expected 422, got ${status}`);
      assert.ok(data?.error, `Expected error field, got ${JSON.stringify(data)}`);
    });
  });

  describe('POST /v1/:keyName/decrypt', () => {
    it('decrypts ciphertext and returns plaintext', async () => {
      const enc = await request('POST', '/v1/vault/encrypt', { plaintext: 'roundtrip test' });
      assert.strictEqual(enc.status, 200, 'encrypt should succeed');
      const { status, data } = await request('POST', '/v1/vault/decrypt', { ciphertext: enc.data.ciphertext });
      assert.strictEqual(status, 200, `Expected 200, got ${status}`);
      assert.strictEqual(data?.plaintext, 'roundtrip test', `Expected plaintext match, got ${JSON.stringify(data)}`);
    });

    it('returns 422 for invalid ciphertext format', async () => {
      const { status, data } = await request('POST', '/v1/vault/decrypt', { ciphertext: 'not-valid-format' });
      assert.strictEqual(status, 422, `Expected 422, got ${status}`);
      assert.ok(data?.error, `Expected error field, got ${JSON.stringify(data)}`);
    });

    it('returns 422 for missing ciphertext', async () => {
      const { status, data } = await request('POST', '/v1/vault/decrypt', {});
      assert.strictEqual(status, 422, `Expected 422, got ${status}`);
      assert.ok(data?.error, `Expected error field, got ${JSON.stringify(data)}`);
    });

    it('returns 500 for key version not found', async () => {
      const { status, data } = await request('POST', '/v1/vault/decrypt', {
        ciphertext: 'v99:deadbeef:000000000000000000000000',
      });
      assert.strictEqual(status, 500, `Expected 500, got ${status}`);
      assert.ok(data?.error?.includes('key not found') || data?.error?.includes('version'), `Expected key not found error, got ${JSON.stringify(data)}`);
    });
  });

  describe('POST /v1/:keyName/rotate', () => {
    it('re-encrypts ciphertext and preserves plaintext', async () => {
      const enc = await request('POST', '/v1/vault/encrypt', { plaintext: 'data to rotate' });
      assert.strictEqual(enc.status, 200, 'encrypt should succeed');
      assert.ok(enc.data.ciphertext.startsWith('v') && enc.data.ciphertext.includes(':'), 'ciphertext should be in v{version}:{hex}:{hex} format');

      const rot = await request('POST', '/v1/vault/rotate', { ciphertext: enc.data.ciphertext });
      assert.strictEqual(rot.status, 200, `Expected 200, got ${rot.status}`);
      assert.ok(typeof rot.data?.ciphertext === 'string', `Expected { ciphertext: string }, got ${JSON.stringify(rot.data)}`);

      const dec = await request('POST', '/v1/vault/decrypt', { ciphertext: rot.data.ciphertext });
      assert.strictEqual(dec.status, 200, 'decrypt should succeed');
      assert.strictEqual(dec.data?.plaintext, 'data to rotate', 'rotated ciphertext should decrypt to original');
    });

    it('returns 422 for invalid ciphertext format', async () => {
      const { status, data } = await request('POST', '/v1/vault/rotate', { ciphertext: 'invalid' });
      assert.strictEqual(status, 422, `Expected 422, got ${status}`);
      assert.ok(data?.error, `Expected error field, got ${JSON.stringify(data)}`);
    });
  });

  describe('routing', () => {
    it('returns 404 for unknown path', async () => {
      const { status } = await request('GET', '/v1/vault/unknown');
      assert.strictEqual(status, 404, `Expected 404, got ${status}`);
    });

    it('version does not accept POST', async () => {
      const { status } = await request('POST', '/v1/vault/version', {});
      assert.ok(status === 404 || status === 405, `Expected 404 or 405, got ${status}`);
    });
  });
});
