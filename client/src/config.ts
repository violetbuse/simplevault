/**
 * Simplified dev server config. Same structure as Rust config but without
 * delete-after, env var, or other security features.
 */

export interface DevConfig {
  api_keys: ApiKeyConfigEntry[];
  server_port: number;
  keys: Record<string, Record<string, string>>;
  outbound_destinations?: Record<string, OutboundDestinationRule[]>;
}

export type ApiKeyOperation = 'encrypt' | 'decrypt' | 'rotate' | 'verify' | 'sign' | 'proxy';

export interface ApiKeyConfigObject {
  value: string;
  keys?: 'all' | string[];
  operations?: 'all' | ApiKeyOperation[];
}

export type ApiKeyConfigEntry = string | ApiKeyConfigObject;

export interface OutboundDestinationRule {
  host: string;
  path_prefix?: string;
  methods?: string[];
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
  outbound_destinations: {},
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
    parsed.api_keys = parsed.api_keys
      .map((entry) => normalizeApiKeyEntry(entry))
      .filter((entry): entry is ApiKeyConfigEntry => entry !== null);
    if (!parsed.keys || typeof parsed.keys !== 'object') {
      parsed.keys = DEFAULT_DEV_CONFIG.keys;
    }
    if (!parsed.outbound_destinations || typeof parsed.outbound_destinations !== 'object') {
      parsed.outbound_destinations = {};
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

function normalizeApiKeyEntry(entry: unknown): ApiKeyConfigEntry | null {
  if (typeof entry === 'string') {
    return entry;
  }
  if (typeof entry !== 'object' || entry === null) {
    return null;
  }
  const objectEntry = entry as Record<string, unknown>;
  if (typeof objectEntry.value !== 'string') {
    return null;
  }
  const normalized: ApiKeyConfigObject = {
    value: objectEntry.value,
  };
  if (objectEntry.keys === 'all') {
    normalized.keys = 'all';
  } else if (Array.isArray(objectEntry.keys) && objectEntry.keys.every((item) => typeof item === 'string')) {
    normalized.keys = objectEntry.keys;
  }
  if (objectEntry.operations === 'all') {
    normalized.operations = 'all';
  } else if (
    Array.isArray(objectEntry.operations) &&
    objectEntry.operations.every((item) => typeof item === 'string')
  ) {
    normalized.operations = objectEntry.operations as ApiKeyOperation[];
  }
  return normalized;
}

export function writeDefaultConfig(path: string = DEFAULT_CONFIG_PATH): void {
  const content = JSON.stringify(DEFAULT_DEV_CONFIG, null, 2);
  writeFileSync(path, content, 'utf8');
}
