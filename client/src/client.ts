/**
 * SimpleVault API client for encrypt, decrypt, rotate, create-signature, verify-signature, and version.
 */

export interface SimpleVaultClientOptions {
  /** Base URL of the SimpleVault server (e.g. http://localhost:8080) */
  baseUrl: string;
  /** Optional API key for authentication (Bearer / x-api-key) */
  apiKey?: string;
}

export interface VerifySignatureParams {
  ciphertext: string;
  payload: string;
  signature: string;
  algorithm: 'hmac-sha1' | 'sha1' | 'hmac-sha256' | 'sha256' | 'hmac-sha512' | 'sha512';
}

export interface CreateSignatureParams {
  ciphertext: string;
  payload: string;
  algorithm: 'hmac-sha1' | 'sha1' | 'hmac-sha256' | 'sha256' | 'hmac-sha512' | 'sha512';
}

export interface ProxySubstituteRequest {
  ciphertext: string;
  request: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
  };
  placeholder?: string;
}

export interface ProxySubstituteResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export interface DbQueryRequest {
  ciphertext: string;
  query: {
    sql: string;
    params?: Array<
      | string
      | number
      | boolean
      | null
      | Record<string, unknown>
      | unknown[]
      | {
          param_type:
            | 'null'
            | 'bool'
            | 'boolean'
            | 'int'
            | 'smallint'
            | 'int2'
            | 'i16'
            | 'int4'
            | 'integer'
            | 'i32'
            | 'bigint'
            | 'int8'
            | 'i64'
            | 'float'
            | 'float8'
            | 'double'
            | 'f64'
            | 'text'
            | 'varchar'
            | 'string'
            | 'timestamptz'
            | 'timestamp with time zone'
            | 'timestamp'
            | 'timestamp without time zone'
            | 'date'
            | 'time'
            | 'uuid'
            | 'bytea'
            | 'json'
            | 'jsonb';
          value?: unknown;
        }
    >;
  };
  options?: {
    timeout_ms?: number;
    max_rows?: number;
  };
}

export interface DbQueryResponse {
  columns: Array<{ name: string; db_type?: string }>;
  rows: unknown[][];
  row_count: number;
  truncated: boolean;
  timing_ms: number;
}

export class SimpleVaultClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;

  constructor(options: SimpleVaultClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.apiKey = options.apiKey;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: object
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
      headers['x-api-key'] = this.apiKey;
    }

    const res = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    const text = await res.text();
    let data: unknown;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      throw new Error(`Invalid JSON response: ${text.slice(0, 200)}`);
    }

    if (!res.ok) {
      const err = (data as { error?: string })?.error ?? res.statusText;
      throw new Error(`SimpleVault ${res.status}: ${err}`);
    }

    return data as T;
  }

  /**
   * Encrypt plaintext using the latest key version.
   */
  async encrypt(keyName: string, plaintext: string): Promise<{ ciphertext: string }> {
    return this.request('POST', `/v1/${encodeURIComponent(keyName)}/encrypt`, {
      plaintext,
    });
  }

  /**
   * Decrypt ciphertext. Key version is embedded in the ciphertext.
   */
  async decrypt(keyName: string, ciphertext: string): Promise<{ plaintext: string }> {
    return this.request('POST', `/v1/${encodeURIComponent(keyName)}/decrypt`, {
      ciphertext,
    });
  }

  /**
   * Re-encrypt ciphertext with the latest key version (key rotation).
   */
  async rotate(keyName: string, ciphertext: string): Promise<{ ciphertext: string }> {
    return this.request('POST', `/v1/${encodeURIComponent(keyName)}/rotate`, {
      ciphertext,
    });
  }

  /**
   * Create a signature for a hex-encoded payload.
   * The ciphertext is decrypted server-side and used as the HMAC secret.
   */
  async createSignature(
    keyName: string,
    params: CreateSignatureParams
  ): Promise<{ signature: string }> {
    return this.request('POST', `/v1/${encodeURIComponent(keyName)}/create-signature`, {
      ciphertext: params.ciphertext,
      payload: params.payload,
      algorithm: params.algorithm,
    });
  }

  /**
   * Verify signature against a hex-encoded payload.
   * The ciphertext is decrypted server-side and used as the HMAC secret.
   */
  async verifySignature(
    keyName: string,
    params: VerifySignatureParams
  ): Promise<{ verified: boolean }> {
    return this.request('POST', `/v1/${encodeURIComponent(keyName)}/verify-signature`, {
      ciphertext: params.ciphertext,
      payload: params.payload,
      signature: params.signature,
      algorithm: params.algorithm,
    });
  }

  /**
   * Get the latest key version number for a key name.
   */
  async getVersion(keyName: string): Promise<{ version: number }> {
    return this.request('GET', `/v1/${encodeURIComponent(keyName)}/version`);
  }

  /**
   * Decrypt ciphertext and substitute plaintext into an outbound request.
   * The outbound response is returned as JSON payload with status/headers/body.
   */
  async proxySubstitute(
    keyName: string,
    params: ProxySubstituteRequest
  ): Promise<ProxySubstituteResponse> {
    return this.request('POST', `/v1/${encodeURIComponent(keyName)}/proxy-substitute`, params);
  }

  /**
   * Decrypts a ciphertext DB connection string server-side and executes a query.
   */
  async dbQuery(
    keyName: string,
    params: DbQueryRequest
  ): Promise<DbQueryResponse> {
    return this.request('POST', `/v1/${encodeURIComponent(keyName)}/db-query`, params);
  }
}
