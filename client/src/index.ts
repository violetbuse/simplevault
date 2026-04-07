/**
 * SimpleVault — Node.js client for the SimpleVault encryption HTTP API.
 *
 * For local development, run the official Rust server binary against a config file
 * (see project README and documentation); point this client at that base URL.
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
 */

export { SimpleVaultClient } from './client.js';
export type {
  CreateSignatureParams,
  ProxySubstituteRequest,
  ProxySubstituteResponse,
  DbQueryRequest,
  DbQueryResponse,
  SimpleVaultClientOptions,
  VerifySignatureParams,
} from './client.js';
