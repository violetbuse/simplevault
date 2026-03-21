/**
 * SimpleVault - Client library and dev server for the SimpleVault encryption API.
 *
 * @example
 * ```ts
 * import { SimpleVaultClient } from 'simplevault';
 *
 * const client = new SimpleVaultClient({
 *   baseUrl: 'http://localhost:8080',
 *   apiKey: 'optional-key',
 * });
 *
 * const { ciphertext } = await client.encrypt('vault', 'secret');
 * const { plaintext } = await client.decrypt('vault', ciphertext);
 * ```
 *
 * Dev server: `npx simplevault-dev` or `npx simplevault-dev --port 3000 --config ./config.json`
 */

export { SimpleVaultClient } from './client.js';
export type {
  CreateSignatureParams,
  ProxySubstituteRequest,
  ProxySubstituteResponse,
  SimpleVaultClientOptions,
  VerifySignatureParams,
} from './client.js';
export {
  runDevServer,
  runDevServerWithWatch,
  createDevServer,
} from './server.js';
export type { DevServerWatchOptions } from './server.js';
export {
  loadConfig,
  writeDefaultConfig,
  DEFAULT_DEV_CONFIG,
  DEFAULT_CONFIG_PATH,
} from './config.js';
export type { DevConfig } from './config.js';
