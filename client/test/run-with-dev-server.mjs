#!/usr/bin/env node
/**
 * Starts the dev server, runs contract tests, then stops the server.
 * For CI: no extra deps, uses tsx (already in devDependencies).
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { createServer } from 'node:net';

const __dirname = dirname(fileURLToPath(import.meta.url));

async function findFreePort() {
  return await new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        server.close(() => reject(new Error('failed to allocate free port')));
        return;
      }
      const { port } = address;
      server.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

async function waitForServer(baseUrl, maxAttempts = 80, intervalMs = 250) {
  const apiKey = process.env.SIMPLEVAULT_API_KEY || 'contract-test-key';
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const res = await fetch(`${baseUrl}/v1/vault/version`, {
        headers: { 'x-api-key': apiKey },
      });
      if (res.ok) return true;
    } catch {
      // not ready yet
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return false;
}

function killAndWait(server, maxWaitMs = 5000) {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      if (server.exitCode === null) {
        if (process.platform !== 'win32') {
          try { process.kill(-server.pid, 'SIGKILL'); } catch { server.kill('SIGKILL'); }
        } else {
          server.kill('SIGKILL');
        }
      }
      resolve();
    }, maxWaitMs);
    const onExit = () => {
      clearTimeout(timeout);
      resolve();
    };
    server.once('exit', onExit);
    server.once('close', onExit);
    if (process.platform !== 'win32') {
      try { process.kill(-server.pid, 'SIGTERM'); } catch { server.kill('SIGTERM'); }
    } else {
      server.kill('SIGTERM');
    }
    if (server.exitCode !== null) onExit();
  });
}

function runTests(baseUrl) {
  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      ['--test', join(__dirname, 'contract.mjs')],
      {
        cwd: join(__dirname, '..'),
        env: { ...process.env, SIMPLEVAULT_BASE_URL: baseUrl },
        stdio: 'inherit',
      }
    );
    child.on('close', (code) => resolve(code ?? 1));
  });
}

function createRuntimeConfigPath() {
  const baseConfigPath = join(__dirname, 'config.json');
  const runtimeConfigPath = join(__dirname, `config.runtime.${process.pid}.json`);
  const parsed = JSON.parse(readFileSync(baseConfigPath, 'utf8'));
  const testDbUrl = process.env.SIMPLEVAULT_TEST_DB_URL;
  if (testDbUrl) {
    const url = new URL(testDbUrl);
    const host = url.hostname;
    const port = url.port ? Number.parseInt(url.port, 10) : 5432;
    if (!parsed.db_destinations) {
      parsed.db_destinations = {};
    }
    parsed.db_destinations.vault = [{ host, port }];
    parsed.db_destinations.readonly = [{ host, port, access: 'read_only' }];
  }
  writeFileSync(runtimeConfigPath, JSON.stringify(parsed, null, 2), 'utf8');
  return runtimeConfigPath;
}

async function main() {
  const port = await findFreePort();
  const baseUrl = `http://localhost:${port}`;
  const configPath = createRuntimeConfigPath();
  const server = spawn(
    'npx',
    ['tsx', 'src/cli.ts', '-c', configPath, '-p', String(port)],
    {
      cwd: join(__dirname, '..'),
      stdio: 'inherit',
      detached: true,
    }
  );

  let exitCode = 1;
  try {
    const ready = await waitForServer(baseUrl);
    if (!ready) {
      console.error(`Dev server did not become ready in time at ${baseUrl}`);
      process.exit(1);
    }

    exitCode = await runTests(baseUrl);
  } finally {
    await killAndWait(server, 5000);
    try {
      unlinkSync(configPath);
    } catch {
      // ignore cleanup errors
    }
  }

  process.exit(exitCode);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
