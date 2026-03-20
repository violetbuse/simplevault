/**
 * Dev server that emulates the SimpleVault Rust API.
 * Uses simplified config (no delete-after, env vars, etc).
 */

import { watch } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import type { Request, Response, NextFunction } from 'express';
import express from 'express';
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

export function createDevServer(config: DevConfig): express.Application {
  const app = express();

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
