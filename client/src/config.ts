/**
 * Simplified dev server config. Same structure as Rust config but without
 * delete-after, env var, or other security features.
 */

export interface DevConfig {
  api_keys: string[];
  server_port: number;
  keys: Record<string, Record<string, string>>;
}

const DEFAULT_KEY =
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

export const DEFAULT_DEV_CONFIG: DevConfig = {
  api_keys: [],
  server_port: 8080,
  keys: {
    vault: {
      '1': DEFAULT_KEY,
    },
  },
};

/** Default config file path used by init and as default for dev. */
export const DEFAULT_CONFIG_PATH = 'simplevault.config.json';

import { readFileSync, writeFileSync } from 'node:fs';

export function loadConfig(configPath?: string): DevConfig {
  if (!configPath) {
    return { ...DEFAULT_DEV_CONFIG };
  }
  try {
    const content = readFileSync(configPath, 'utf8');
    const parsed = JSON.parse(content) as DevConfig;
    if (typeof parsed.server_port !== 'number') {
      parsed.server_port = 8080;
    }
    if (!Array.isArray(parsed.api_keys)) {
      parsed.api_keys = [];
    }
    if (!parsed.keys || typeof parsed.keys !== 'object') {
      parsed.keys = DEFAULT_DEV_CONFIG.keys;
    }
    return parsed;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === 'ENOENT') {
      writeDefaultConfig(configPath);
      return { ...DEFAULT_DEV_CONFIG };
    }
    throw new Error(`Failed to load config from ${configPath}: ${(err as Error).message}`);
  }
}

export function writeDefaultConfig(path: string = DEFAULT_CONFIG_PATH): void {
  const content = JSON.stringify(DEFAULT_DEV_CONFIG, null, 2);
  writeFileSync(path, content, 'utf8');
}
