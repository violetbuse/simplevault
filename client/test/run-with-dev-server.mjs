#!/usr/bin/env node
/**
 * Starts the dev server, runs contract tests, then stops the server.
 * For CI: no extra deps, uses tsx (already in devDependencies).
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = 8080;
const BASE_URL = `http://localhost:${PORT}`;

async function waitForServer(maxAttempts = 20, intervalMs = 250) {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const res = await fetch(`${BASE_URL}/v1/vault/version`);
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

function runTests() {
  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      ['--test', join(__dirname, 'contract.mjs')],
      {
        cwd: join(__dirname, '..'),
        env: { ...process.env, SIMPLEVAULT_BASE_URL: BASE_URL },
        stdio: 'inherit',
      }
    );
    child.on('close', (code) => resolve(code ?? 1));
  });
}

async function main() {
  const configPath = join(__dirname, 'config.json');
  const server = spawn(
    'npx',
    ['tsx', 'src/cli.ts', '-c', configPath, '-p', String(PORT)],
    {
      cwd: join(__dirname, '..'),
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true,
    }
  );

  let exitCode = 1;
  try {
    const ready = await waitForServer();
    if (!ready) {
      console.error('Dev server did not become ready in time');
      process.exit(1);
    }

    exitCode = await runTests();
  } finally {
    await killAndWait(server, 5000);
  }

  process.exit(exitCode);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
