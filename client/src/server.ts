/**
 * Dev server that emulates the SimpleVault Rust API.
 * Uses simplified config (no delete-after, env vars, etc).
 */

import { watch } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import express from 'express';
import pg from 'pg';
import * as crypto from './crypto.js';
import { loadConfig } from './config.js';
import type { ApiKeyConfigEntry, ApiKeyOperation, DevConfig } from './config.js';

function getLatestKey(
  config: DevConfig,
  keyName: string
): { version: number; key: crypto.EncryptionKey } | null {
  const versions = config.keys[keyName];
  if (!versions || typeof versions !== 'object') return null;
  const versionNumbers = Object.keys(versions)
    .map((v) => parseInt(v, 10))
    .filter((n) => !isNaN(n));
  if (versionNumbers.length === 0) return null;
  const latest = Math.max(...versionNumbers);
  const hexKey = versions[String(latest)];
  if (!hexKey || !crypto.isValidKeyHex(hexKey)) return null;
  return { version: latest, key: crypto.parseKey(hexKey) };
}

function getKey(
  config: DevConfig,
  keyName: string,
  version: number
): crypto.EncryptionKey | null {
  const versions = config.keys[keyName];
  if (!versions || typeof versions !== 'object') return null;
  const hexKey = versions[String(version)];
  if (!hexKey || !crypto.isValidKeyHex(hexKey)) return null;
  return crypto.parseKey(hexKey);
}

function extractApiKey(req: Request): string | null {
  const auth = req.headers.authorization;
  if (auth?.startsWith('Bearer ')) {
    return auth.slice(7).trim();
  }
  const xApiKey = req.headers['x-api-key'];
  if (typeof xApiKey === 'string') {
    return xApiKey.trim();
  }
  const q = req.query.api_key;
  if (typeof q === 'string') return q;
  return null;
}

function createAuthMiddleware(config: DevConfig) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (config.api_keys.length === 0) {
      next();
      return;
    }
    const key = extractApiKey(req);
    const matched = getMatchingApiKey(config, key);
    if (key === null || matched === null) {
      res.status(401).json({ error: 'missing or invalid API key' });
      return;
    }
    res.locals.authenticatedApiKey = matched;
    next();
  };
}

function getMatchingApiKey(config: DevConfig, key: string | null): ApiKeyConfigEntry | null {
  if (key === null) {
    return null;
  }
  for (const apiKey of config.api_keys) {
    if (typeof apiKey === 'string') {
      if (apiKey === key) {
        return apiKey;
      }
      continue;
    }
    if (apiKey.value === key) {
      return apiKey;
    }
  }
  return null;
}

function apiKeyAllowsKeyName(apiKey: ApiKeyConfigEntry, keyName: string): boolean {
  if (typeof apiKey === 'string') {
    return true;
  }
  if (apiKey.keys === undefined || apiKey.keys === 'all') {
    return true;
  }
  return apiKey.keys.includes(keyName);
}

function apiKeyAllowsOperation(apiKey: ApiKeyConfigEntry, operation: ApiKeyOperation): boolean {
  if (typeof apiKey === 'string') {
    return true;
  }
  if (apiKey.operations === undefined || apiKey.operations === 'all') {
    return true;
  }
  return apiKey.operations.includes(operation);
}

function checkScope(config: DevConfig, req: Request, keyName: string, operation: ApiKeyOperation): string | null {
  if (config.api_keys.length === 0) {
    return null;
  }
  const apiKey = resLocalApiKey(req);
  if (apiKey === null) {
    return 'missing or invalid API key';
  }
  if (!apiKeyAllowsKeyName(apiKey, keyName)) {
    return 'API key not allowed for this key';
  }
  if (!apiKeyAllowsOperation(apiKey, operation)) {
    return 'API key not allowed for this operation';
  }
  return null;
}

function resLocalApiKey(req: Request): ApiKeyConfigEntry | null {
  return (req.res?.locals?.authenticatedApiKey ?? null) as ApiKeyConfigEntry | null;
}

function destinationAllowed(
  config: DevConfig,
  keyName: string,
  method: string,
  host: string,
  path: string
): boolean {
  const rules = config.outbound_destinations?.[keyName];
  if (!rules) {
    return true;
  }
  return rules.some((rule) => {
    if (rule.host.toLowerCase() !== host.toLowerCase()) {
      return false;
    }
    if (rule.path_prefix && !path.startsWith(rule.path_prefix)) {
      return false;
    }
    if (rule.methods && !rule.methods.some((ruleMethod) => ruleMethod.toUpperCase() === method.toUpperCase())) {
      return false;
    }
    return true;
  });
}

const DEFAULT_DB_QUERY_TIMEOUT_MS = 5000;
const DEFAULT_DB_QUERY_MAX_ROWS = 500;
const DB_POOL_IDLE_EVICT_MS = 60_000;
const DB_POOL_SWEEP_MS = 5_000;

type DbPoolEntry = {
  pool: pg.Pool;
  lastUsedAt: number;
};

class DbPoolCache {
  private readonly entries = new Map<string, DbPoolEntry>();
  private readonly evictTimer: NodeJS.Timeout;

  constructor() {
    this.evictTimer = setInterval(() => this.evictIdle(), DB_POOL_SWEEP_MS);
    this.evictTimer.unref();
  }

  private evictIdle(): void {
    const now = Date.now();
    for (const [key, entry] of this.entries.entries()) {
      if (now - entry.lastUsedAt > DB_POOL_IDLE_EVICT_MS) {
        void entry.pool.end().catch(() => undefined);
        this.entries.delete(key);
      }
    }
  }

  getOrCreate(hash: string, connectionString: string): pg.Pool {
    const existing = this.entries.get(hash);
    if (existing) {
      existing.lastUsedAt = Date.now();
      return existing.pool;
    }
    const pool = new pg.Pool({
      connectionString,
      max: 16,
      idleTimeoutMillis: DB_POOL_IDLE_EVICT_MS,
    });
    this.entries.set(hash, { pool, lastUsedAt: Date.now() });
    return pool;
  }
}

function hashConnectionString(connectionString: string): string {
  return createHash('sha256').update(connectionString).digest('hex');
}

function parseConnectionTargets(connectionString: string): Array<{ host: string; port: number }> {
  let parsed: URL;
  try {
    parsed = new URL(connectionString);
  } catch {
    throw new Error('invalid database connection string URL');
  }
  if (parsed.protocol !== 'postgres:' && parsed.protocol !== 'postgresql:') {
    throw new Error('only postgres/postgresql connection strings are supported');
  }
  if (!parsed.hostname) {
    throw new Error('connection string must include a host');
  }
  const port = parsed.port ? Number(parsed.port) : 5432;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('connection string contains an invalid port');
  }
  return [{ host: parsed.hostname, port }];
}

function dbDestinationAllowed(config: DevConfig, keyName: string, host: string, port: number): boolean {
  const rules = config.db_destinations?.[keyName];
  if (!rules) {
    return true;
  }
  return rules.some((rule) => {
    if (rule.host.toLowerCase() !== host.toLowerCase()) {
      return false;
    }
    if (typeof rule.port === 'number' && rule.port !== port) {
      return false;
    }
    return true;
  });
}

function parseDbParams(
  values: unknown
): Array<string | number | boolean | null | Buffer | Record<string, unknown> | unknown[]> {
  if (!Array.isArray(values)) {
    return [];
  }
  return values.map((value) => {
    if (
      value === null ||
      typeof value === 'string' ||
      typeof value === 'number' ||
      typeof value === 'boolean'
    ) {
      return value;
    }
    if (Array.isArray(value)) {
      return JSON.stringify(value);
    }
    if (typeof value === 'object' && value !== null) {
      const maybeTyped = value as Record<string, unknown>;
      const strictTypedShape =
        Object.keys(maybeTyped).length === 2 &&
        Object.prototype.hasOwnProperty.call(maybeTyped, 'param_type') &&
        Object.prototype.hasOwnProperty.call(maybeTyped, 'value') &&
        typeof maybeTyped.param_type === 'string';
      if (strictTypedShape) {
        const normalizedType = (maybeTyped.param_type as string).trim().toLowerCase();
        const typedValue = maybeTyped.value;
        switch (normalizedType) {
          case 'null':
            return null;
          case 'bool':
          case 'boolean':
            if (typeof typedValue !== 'boolean') {
              throw new Error('typed param bool requires a boolean value');
            }
            return typedValue;
          case 'int':
          case 'int4':
          case 'integer':
          case 'i32':
          case 'smallint':
          case 'int2':
          case 'i16':
          case 'bigint':
          case 'int8':
          case 'i64':
          case 'float':
          case 'float8':
          case 'double':
          case 'f64':
            if (typeof typedValue !== 'number') {
              throw new Error(`typed param ${normalizedType} requires a numeric value`);
            }
            return typedValue;
          case 'timestamptz':
          case 'timestamp with time zone':
          case 'timestamp':
          case 'timestamp without time zone':
          case 'date':
          case 'time':
          case 'uuid':
            if (typeof typedValue !== 'string') {
              throw new Error(`typed param ${normalizedType} requires a string value`);
            }
            return typedValue;
          case 'bytea':
            if (typeof typedValue !== 'string') {
              throw new Error('typed param bytea requires a hex string value');
            }
            return Buffer.from(typedValue.replace(/^\\x|^0x/i, ''), 'hex');
          case 'text':
          case 'varchar':
          case 'string':
            if (typeof typedValue !== 'string') {
              throw new Error('typed param text/varchar requires a string value');
            }
            return typedValue;
          case 'json':
          case 'jsonb':
          return JSON.stringify(typedValue);
          default:
            throw new Error(`unsupported typed param type: ${normalizedType}`);
        }
      }
      return JSON.stringify(value);
    }
    throw new Error('query params support only null, bool, number, and string values');
  });
}

function formatPgError(error: unknown): string {
  if (error instanceof Error) {
    const pgLike = error as Error & {
      code?: string;
      detail?: string;
      hint?: string;
      position?: string | number;
    };
    if (typeof pgLike.code === 'string') {
      const parts = [`database error [${pgLike.code}]: ${error.message}`];
      if (typeof pgLike.detail === 'string' && pgLike.detail.trim().length > 0) {
        parts.push(`detail: ${pgLike.detail}`);
      }
      if (typeof pgLike.hint === 'string' && pgLike.hint.trim().length > 0) {
        parts.push(`hint: ${pgLike.hint}`);
      }
      if (pgLike.position !== undefined) {
        parts.push(`position: ${String(pgLike.position)}`);
      }
      return parts.join(' | ');
    }
    return error.message;
  }
  return String(error);
}

export function createDevServer(config: DevConfig): express.Application {
  const app = express();
  const dbPoolCache = new DbPoolCache();

  app.use(express.json());
  app.use(createAuthMiddleware(config));

  app.get('/v1/:keyName/version', (req, res) => {
    const { keyName } = req.params;
    const latest = getLatestKey(config, keyName);
    if (!latest) {
      res.status(500).json({ error: `key not found: ${keyName}` });
      return;
    }
    res.json({ version: latest.version });
  });

  app.post('/v1/:keyName/encrypt', (req, res) => {
    const { keyName } = req.params;
    const scopeError = checkScope(config, req, keyName, 'encrypt');
    if (scopeError) {
      res.status(403).json({ error: scopeError });
      return;
    }
    const plaintext = req.body?.plaintext;
    if (typeof plaintext !== 'string') {
      res.status(422).json({ error: 'missing or invalid plaintext field' });
      return;
    }
    const latest = getLatestKey(config, keyName);
    if (!latest) {
      res.status(500).json({ error: `key not found: ${keyName}` });
      return;
    }
    const ciphertext = crypto.encrypt(plaintext, latest.key, latest.version);
    res.json({ ciphertext });
  });

  app.post('/v1/:keyName/decrypt', (req, res) => {
    const { keyName } = req.params;
    const scopeError = checkScope(config, req, keyName, 'decrypt');
    if (scopeError) {
      res.status(403).json({ error: scopeError });
      return;
    }
    const ciphertext = req.body?.ciphertext;
    if (typeof ciphertext !== 'string') {
      res.status(422).json({ error: 'missing or invalid ciphertext field' });
      return;
    }
    let parsed: { keyVersion: number };
    try {
      parsed = crypto.parseCipherText(ciphertext);
    } catch {
      res.status(422).json({ error: 'invalid ciphertext format' });
      return;
    }
    const key = getKey(config, keyName, parsed.keyVersion);
    if (!key) {
      res.status(500).json({
        error: `key not found: ${keyName} (version ${parsed.keyVersion})`,
      });
      return;
    }
    try {
      const plaintext = crypto.decrypt(ciphertext, key);
      res.json({ plaintext: plaintext.toString('utf8') });
    } catch {
      res.status(500).json({ error: 'decryption failed' });
    }
  });

  app.post('/v1/:keyName/rotate', (req, res) => {
    const { keyName } = req.params;
    const scopeError = checkScope(config, req, keyName, 'rotate');
    if (scopeError) {
      res.status(403).json({ error: scopeError });
      return;
    }
    const ciphertext = req.body?.ciphertext;
    if (typeof ciphertext !== 'string') {
      res.status(422).json({ error: 'missing or invalid ciphertext field' });
      return;
    }
    let parsed: { keyVersion: number };
    try {
      parsed = crypto.parseCipherText(ciphertext);
    } catch {
      res.status(422).json({ error: 'invalid ciphertext format' });
      return;
    }
    const oldKey = getKey(config, keyName, parsed.keyVersion);
    if (!oldKey) {
      res.status(500).json({
        error: `key not found: ${keyName} (version ${parsed.keyVersion})`,
      });
      return;
    }
    const latest = getLatestKey(config, keyName);
    if (!latest) {
      res.status(500).json({ error: `key not found: ${keyName}` });
      return;
    }
    try {
      const plaintext = crypto.decrypt(ciphertext, oldKey);
      const newCiphertext = crypto.encrypt(plaintext, latest.key, latest.version);
      res.json({ ciphertext: newCiphertext });
    } catch {
      res.status(500).json({ error: 'decryption or encryption failed' });
    }
  });

  app.post('/v1/:keyName/verify-signature', (req, res) => {
    const { keyName } = req.params;
    const scopeError = checkScope(config, req, keyName, 'verify');
    if (scopeError) {
      res.status(403).json({ error: scopeError });
      return;
    }
    const ciphertext = req.body?.ciphertext;
    const payloadHex = req.body?.payload;
    const signatureHex = req.body?.signature;
    const algorithm = req.body?.algorithm;

    if (
      typeof ciphertext !== 'string' ||
      typeof payloadHex !== 'string' ||
      typeof signatureHex !== 'string' ||
      typeof algorithm !== 'string'
    ) {
      res.status(422).json({
        error: 'missing or invalid fields: ciphertext, payload, signature, algorithm',
      });
      return;
    }

    let parsed: { keyVersion: number };
    try {
      parsed = crypto.parseCipherText(ciphertext);
    } catch {
      res.status(422).json({ error: 'invalid ciphertext format' });
      return;
    }

    const key = getKey(config, keyName, parsed.keyVersion);
    if (!key) {
      res.status(500).json({
        error: `key not found: ${keyName} (version ${parsed.keyVersion})`,
      });
      return;
    }

    let payload: Buffer;
    try {
      payload = crypto.decodeHexInput('payload', payloadHex);
    } catch (err) {
      res.status(422).json({ error: (err as Error).message });
      return;
    }

    let signature: Buffer;
    try {
      signature = crypto.decodeHexInput('signature', signatureHex);
    } catch (err) {
      res.status(422).json({ error: (err as Error).message });
      return;
    }

    try {
      const secret = crypto.decrypt(ciphertext, key);
      const verified = crypto.verifyHmacSignature(secret, payload, signature, algorithm);
      res.json({ verified });
    } catch (err) {
      const message = (err as Error).message;
      if (message.startsWith('unsupported signature algorithm')) {
        res.status(500).json({ error: message });
        return;
      }
      res.status(500).json({ error: 'signature verification failed' });
    }
  });

  app.post('/v1/:keyName/create-signature', (req, res) => {
    const { keyName } = req.params;
    const scopeError = checkScope(config, req, keyName, 'sign');
    if (scopeError) {
      res.status(403).json({ error: scopeError });
      return;
    }
    const ciphertext = req.body?.ciphertext;
    const payloadHex = req.body?.payload;
    const algorithm = req.body?.algorithm;

    if (
      typeof ciphertext !== 'string' ||
      typeof payloadHex !== 'string' ||
      typeof algorithm !== 'string'
    ) {
      res.status(422).json({
        error: 'missing or invalid fields: ciphertext, payload, algorithm',
      });
      return;
    }

    let parsed: { keyVersion: number };
    try {
      parsed = crypto.parseCipherText(ciphertext);
    } catch {
      res.status(422).json({ error: 'invalid ciphertext format' });
      return;
    }

    const key = getKey(config, keyName, parsed.keyVersion);
    if (!key) {
      res.status(500).json({
        error: `key not found: ${keyName} (version ${parsed.keyVersion})`,
      });
      return;
    }

    let payload: Buffer;
    try {
      payload = crypto.decodeHexInput('payload', payloadHex);
    } catch (err) {
      res.status(422).json({ error: (err as Error).message });
      return;
    }

    try {
      const secret = crypto.decrypt(ciphertext, key);
      const signature = crypto.createHmacSignature(secret, payload, algorithm);
      res.json({ signature: signature.toString('hex') });
    } catch (err) {
      const message = (err as Error).message;
      if (message.startsWith('unsupported signature algorithm')) {
        res.status(500).json({ error: message });
        return;
      }
      res.status(500).json({ error: 'signature creation failed' });
    }
  });

  app.post('/v1/:keyName/proxy-substitute', async (req, res) => {
    const { keyName } = req.params;
    const scopeError = checkScope(config, req, keyName, 'proxy');
    if (scopeError) {
      res.status(403).json({ error: scopeError });
      return;
    }

    const ciphertext = req.body?.ciphertext;
    const outboundRequest = req.body?.request;
    const placeholder =
      typeof req.body?.placeholder === 'string' && req.body.placeholder.trim() !== ''
        ? req.body.placeholder.trim()
        : '{{SIMPLEVAULT_PLAINTEXT}}';
    if (typeof ciphertext !== 'string' || typeof outboundRequest !== 'object' || outboundRequest === null) {
      res.status(422).json({ error: 'missing or invalid fields: ciphertext, request' });
      return;
    }

    if (typeof outboundRequest.method !== 'string' || typeof outboundRequest.url !== 'string') {
      res.status(422).json({ error: 'request.method and request.url are required strings' });
      return;
    }

    let parsedCiphertext: { keyVersion: number };
    try {
      parsedCiphertext = crypto.parseCipherText(ciphertext);
    } catch {
      res.status(422).json({ error: 'invalid ciphertext format' });
      return;
    }
    const key = getKey(config, keyName, parsedCiphertext.keyVersion);
    if (!key) {
      res.status(500).json({
        error: `key not found: ${keyName} (version ${parsedCiphertext.keyVersion})`,
      });
      return;
    }

    let plaintext: string;
    try {
      plaintext = crypto.decrypt(ciphertext, key).toString('utf8');
    } catch {
      res.status(500).json({ error: 'decryption failed' });
      return;
    }

    const method = outboundRequest.method.toUpperCase();
    const outboundUrlValue = outboundRequest.url.replaceAll(placeholder, plaintext);
    let outboundUrl: URL;
    try {
      outboundUrl = new URL(outboundUrlValue);
    } catch {
      res.status(422).json({ error: 'invalid outbound URL after substitution' });
      return;
    }

    if (
      outboundUrl.protocol !== 'https:' &&
      !(
        outboundUrl.protocol === 'http:' &&
        (outboundUrl.hostname === 'localhost' || outboundUrl.hostname === '127.0.0.1')
      )
    ) {
      res.status(422).json({ error: 'outbound url must use https (http allowed only for localhost)' });
      return;
    }

    if (!destinationAllowed(config, keyName, method, outboundUrl.hostname, outboundUrl.pathname)) {
      res.status(403).json({ error: 'destination is not allowed for this key set' });
      return;
    }

    const outboundHeaders = new Headers();
    if (typeof outboundRequest.headers === 'object' && outboundRequest.headers !== null) {
      for (const [name, value] of Object.entries(outboundRequest.headers as Record<string, unknown>)) {
        if (typeof value !== 'string') {
          continue;
        }
        if (name.toLowerCase() === 'host' || name.toLowerCase() === 'content-length') {
          continue;
        }
        outboundHeaders.set(name, value.replaceAll(placeholder, plaintext));
      }
    }
    let outboundBody: string | undefined = undefined;
    if (typeof outboundRequest.body === 'string') {
      outboundBody = outboundRequest.body.replaceAll(placeholder, plaintext);
    }

    try {
      const upstreamResponse = await fetch(outboundUrl, {
        method,
        headers: outboundHeaders,
        body: outboundBody,
      });
      const responseText = await upstreamResponse.text();
      const responseHeaders: Record<string, string> = {};
      upstreamResponse.headers.forEach((value, name) => {
        if (
          name.toLowerCase() === 'content-length' ||
          name.toLowerCase() === 'transfer-encoding' ||
          name.toLowerCase() === 'connection' ||
          name.toLowerCase() === 'host'
        ) {
          return;
        }
        responseHeaders[name] = value;
      });
      res.status(upstreamResponse.status).json({
        status: upstreamResponse.status,
        headers: responseHeaders,
        body: responseText,
      });
    } catch (error) {
      res.status(502).json({ error: `upstream request failed: ${(error as Error).message}` });
    }
  });

  app.post('/v1/:keyName/db-query', async (req, res) => {
    const { keyName } = req.params;
    const scopeError = checkScope(config, req, keyName, 'db_query');
    if (scopeError) {
      res.status(403).json({ error: scopeError });
      return;
    }

    const ciphertext = req.body?.ciphertext;
    const queryObject = req.body?.query;
    if (typeof ciphertext !== 'string' || typeof queryObject !== 'object' || queryObject === null) {
      res.status(422).json({ error: 'missing or invalid fields: ciphertext, query' });
      return;
    }
    if (typeof queryObject.sql !== 'string') {
      res.status(422).json({ error: 'query.sql is required and must be a string' });
      return;
    }
    if (queryObject.sql.includes(';')) {
      res.status(422).json({ error: 'query.sql cannot contain semicolons or multiple statements' });
      return;
    }

    let parsedCiphertext: { keyVersion: number };
    try {
      parsedCiphertext = crypto.parseCipherText(ciphertext);
    } catch {
      res.status(422).json({ error: 'invalid ciphertext format' });
      return;
    }
    const key = getKey(config, keyName, parsedCiphertext.keyVersion);
    if (!key) {
      res.status(500).json({
        error: `key not found: ${keyName} (version ${parsedCiphertext.keyVersion})`,
      });
      return;
    }

    let connectionString = '';
    try {
      connectionString = crypto.decrypt(ciphertext, key).toString('utf8');
    } catch {
      res.status(500).json({ error: 'decryption failed' });
      return;
    }

    let targets: Array<{ host: string; port: number }>;
    try {
      targets = parseConnectionTargets(connectionString);
    } catch (error) {
      connectionString = '';
      res.status(422).json({ error: `invalid database connection string: ${(error as Error).message}` });
      return;
    }
    for (const target of targets) {
      if (!dbDestinationAllowed(config, keyName, target.host, target.port)) {
        connectionString = '';
        res.status(403).json({ error: 'database destination is not allowed for this key set' });
        return;
      }
    }

    const hash = hashConnectionString(connectionString);
    const pool = dbPoolCache.getOrCreate(hash, connectionString);
    connectionString = '';

    let params: Array<string | number | boolean | null | Buffer | Record<string, unknown> | unknown[]>;
    try {
      params = parseDbParams(queryObject.params);
    } catch (error) {
      res.status(422).json({ error: (error as Error).message });
      return;
    }
    const timeoutMsRaw = req.body?.options?.timeout_ms;
    const timeoutMs = Math.min(
      Math.max(typeof timeoutMsRaw === 'number' ? Math.floor(timeoutMsRaw) : DEFAULT_DB_QUERY_TIMEOUT_MS, 100),
      60_000
    );
    const maxRowsRaw = req.body?.options?.max_rows;
    const maxRows = Math.min(
      Math.max(typeof maxRowsRaw === 'number' ? Math.floor(maxRowsRaw) : DEFAULT_DB_QUERY_MAX_ROWS, 1),
      10_000
    );

    const wrappedSql = `SELECT row_to_json(simplevault_row) AS simplevault_row_json FROM (${queryObject.sql}) AS simplevault_row`;
    const startedAt = Date.now();
    try {
      const resultPromise = pool.query(wrappedSql, params);
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error('query execution timed out')), timeoutMs);
      });
      const queryResult = await Promise.race([resultPromise, timeoutPromise]);
      const rawRows = (queryResult.rows as Array<{ simplevault_row_json: Record<string, unknown> | null }>).map(
        (row) => row.simplevault_row_json ?? {}
      );
      const columns = rawRows.length > 0 ? Object.keys(rawRows[0]).map((name) => ({ name })) : [];
      const orderedColumnNames = columns.map((column) => column.name);
      const rowCount = rawRows.length;
      const truncated = rowCount > maxRows;
      const slicedRows = truncated ? rawRows.slice(0, maxRows) : rawRows;
      const rows = slicedRows.map((row) =>
        orderedColumnNames.map((columnName) => {
          const value = row[columnName];
          return value === undefined ? null : value;
        })
      );
      res.json({
        columns,
        rows,
        row_count: rowCount,
        truncated,
        timing_ms: Date.now() - startedAt,
      });
    } catch (error) {
      res.status(422).json({ error: formatPgError(error) });
    }
  });

  return app;
}

export function runDevServer(config: DevConfig): Promise<void> {
  return new Promise((resolve, reject) => {
    const app = createDevServer(config);
    const server = app.listen(config.server_port, '0.0.0.0', () => {
      console.warn(
        'WARNING: simplevault dev server is for local development only. Do not use in production.'
      );
      console.log(
        `SimpleVault dev server listening on http://0.0.0.0:${config.server_port}`
      );
      resolve();
    });
    server.on('error', reject);
  });
}

export interface DevServerWatchOptions {
  configPath: string;
  portOverride: number;
}

export function runDevServerWithWatch(options: DevServerWatchOptions): Promise<void> {
  const { configPath, portOverride } = options;
  const absPath = resolve(configPath);

  let server: ReturnType<express.Application['listen']> | null = null;
  let watcher: ReturnType<typeof watch> | null = null;

  function start(): void {
    const cfg = loadConfig(configPath);
    cfg.server_port = portOverride;
    const app = createDevServer(cfg);
    server = app.listen(cfg.server_port, '0.0.0.0', () => {
      console.warn(
        'WARNING: simplevault dev server is for local development only. Do not use in production.'
      );
      console.log(
        `SimpleVault dev server listening on http://0.0.0.0:${cfg.server_port}`
      );
    });
  }

  function stop(): void {
    if (server) {
      server.close();
      server = null;
    }
  }

  function restart(): void {
    stop();
    start();
    console.log('Config changed, restarted.');
  }

  let debounceTimer: ReturnType<typeof setTimeout> | null = null;
  function scheduleRestart(): void {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      debounceTimer = null;
      restart();
    }, 100);
  }

  start();

  const watchDir = dirname(absPath);
  const watchFile = basename(absPath);
  watcher = watch(watchDir, (eventType, filename) => {
    if (filename === watchFile && eventType === 'change') {
      scheduleRestart();
    }
  });

  watcher.on('error', (err) => {
    console.error('Config watcher error:', err);
  });

  return new Promise(() => {});
}
