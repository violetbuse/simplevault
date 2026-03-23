export default function ApiDoc() {
  return (
    <article className="prose prose-invert max-w-none">
      <h1 className="text-3xl font-bold mb-2">API Routes</h1>
      <p className="text-[var(--text-muted)] mb-8">
        All routes use the <code className="bg-black/30 px-1 rounded">/v1/{`{key_name}`}</code> prefix. Replace <code className="bg-black/30 px-1 rounded">key_name</code> with a key defined in your config (e.g. <code className="bg-black/30 px-1 rounded">vault</code>).
      </p>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Authentication</h2>
        <p className="text-[var(--text-muted)] mb-4">
          If <code className="bg-black/30 px-1 rounded">api_keys</code> is non-empty, requests must include a valid API key via one of:
        </p>
        <ul className="text-[var(--text-muted)] space-y-2 mb-4">
          <li><code className="bg-black/30 px-1 rounded">Authorization: Bearer &lt;key&gt;</code></li>
          <li><code className="bg-black/30 px-1 rounded">x-api-key: &lt;key&gt;</code></li>
          <li>Query parameter: <code className="bg-black/30 px-1 rounded">?api_key=&lt;key&gt;</code></li>
        </ul>
        <p className="text-[var(--text-muted)] text-sm">
          Missing or invalid keys return <code className="bg-black/30 px-1 rounded">401 Unauthorized</code>.
        </p>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-6 text-[var(--accent)]">Endpoints</h2>

        <div className="space-y-8">
          <div className="border border-[var(--border)] rounded-lg overflow-hidden bg-[var(--surface-elevated)]">
            <div className="px-5 py-3 border-b border-[var(--border)] flex items-center gap-3">
              <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-green-500/20 text-green-400">POST</span>
              <code className="font-mono text-sm">/v1/{`{key_name}`}/encrypt</code>
            </div>
            <div className="p-5">
              <p className="text-[var(--text-muted)] text-sm mb-4">
                Encrypt plaintext using the latest key version. Returns ciphertext in <code className="bg-black/30 px-1 rounded">v1:&lt;hex&gt;:&lt;nonce&gt;</code> format.
              </p>
              <p className="text-sm font-medium mb-2">Request body:</p>
              <pre className="bg-black/30 rounded p-4 text-sm font-mono mb-4">{`{ "plaintext": "string" }`}</pre>
              <p className="text-sm font-medium mb-2">Response:</p>
              <pre className="bg-black/30 rounded p-4 text-sm font-mono">{`{ "ciphertext": "v1:..." }`}</pre>
            </div>
          </div>

          <div className="border border-[var(--border)] rounded-lg overflow-hidden bg-[var(--surface-elevated)]">
            <div className="px-5 py-3 border-b border-[var(--border)] flex items-center gap-3">
              <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-green-500/20 text-green-400">POST</span>
              <code className="font-mono text-sm">/v1/{`{key_name}`}/decrypt</code>
            </div>
            <div className="p-5">
              <p className="text-[var(--text-muted)] text-sm mb-4">
                Decrypt ciphertext. The key version is embedded in the ciphertext; the server uses the matching key.
              </p>
              <p className="text-sm font-medium mb-2">Request body:</p>
              <pre className="bg-black/30 rounded p-4 text-sm font-mono mb-4">{`{ "ciphertext": "v1:..." }`}</pre>
              <p className="text-sm font-medium mb-2">Response:</p>
              <pre className="bg-black/30 rounded p-4 text-sm font-mono">{`{ "plaintext": "string" }`}</pre>
            </div>
          </div>

          <div className="border border-[var(--border)] rounded-lg overflow-hidden bg-[var(--surface-elevated)]">
            <div className="px-5 py-3 border-b border-[var(--border)] flex items-center gap-3">
              <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-green-500/20 text-green-400">POST</span>
              <code className="font-mono text-sm">/v1/{`{key_name}`}/rotate</code>
            </div>
            <div className="p-5">
              <p className="text-[var(--text-muted)] text-sm mb-4">
                Re-encrypt ciphertext with the latest key version. Decrypts with the original key, then encrypts with the newest. Use for key rotation without exposing plaintext.
              </p>
              <p className="text-sm font-medium mb-2">Request body:</p>
              <pre className="bg-black/30 rounded p-4 text-sm font-mono mb-4">{`{ "ciphertext": "v1:..." }`}</pre>
              <p className="text-sm font-medium mb-2">Response:</p>
              <pre className="bg-black/30 rounded p-4 text-sm font-mono">{`{ "ciphertext": "v3:..." }`}</pre>
            </div>
          </div>

          <div className="border border-[var(--border)] rounded-lg overflow-hidden bg-[var(--surface-elevated)]">
            <div className="px-5 py-3 border-b border-[var(--border)] flex items-center gap-3">
              <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-green-500/20 text-green-400">POST</span>
              <code className="font-mono text-sm">/v1/{`{key_name}`}/create-signature</code>
            </div>
            <div className="p-5">
              <p className="text-[var(--text-muted)] text-sm mb-4">
                Create an HMAC signature using a secret stored as encrypted ciphertext. The server decrypts <code className="bg-black/30 px-1 rounded">ciphertext</code> internally and signs the decoded payload bytes.
              </p>
              <p className="text-sm font-medium mb-2">Request body:</p>
              <pre className="bg-black/30 rounded p-4 text-sm font-mono mb-4">{`{
  "ciphertext": "v1:...",
  "payload": "7b226964223a226576745f74657374227d",
  "algorithm": "hmac-sha256"
}`}</pre>
              <p className="text-sm font-medium mb-2">Response:</p>
              <pre className="bg-black/30 rounded p-4 text-sm font-mono mb-4">{`{ "signature": "2f6d2a0c9f8f1e0f..." }`}</pre>
              <ul className="text-[var(--text-muted)] text-sm space-y-1">
                <li><code className="bg-black/30 px-1 rounded">payload</code> must be hex-encoded bytes.</li>
                <li><code className="bg-black/30 px-1 rounded">signature</code> in the response is hex-encoded bytes.</li>
                <li>Supported algorithms: <code className="bg-black/30 px-1 rounded">hmac-sha1</code>, <code className="bg-black/30 px-1 rounded">hmac-sha256</code>, <code className="bg-black/30 px-1 rounded">hmac-sha512</code> (also <code className="bg-black/30 px-1 rounded">sha1</code>, <code className="bg-black/30 px-1 rounded">sha256</code>, <code className="bg-black/30 px-1 rounded">sha512</code> aliases).</li>
              </ul>
            </div>
          </div>

          <div className="border border-[var(--border)] rounded-lg overflow-hidden bg-[var(--surface-elevated)]">
            <div className="px-5 py-3 border-b border-[var(--border)] flex items-center gap-3">
              <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-green-500/20 text-green-400">POST</span>
              <code className="font-mono text-sm">/v1/{`{key_name}`}/verify-signature</code>
            </div>
            <div className="p-5">
              <p className="text-[var(--text-muted)] text-sm mb-4">
                Verify an HMAC signature using a secret stored as encrypted ciphertext. The server decrypts <code className="bg-black/30 px-1 rounded">ciphertext</code> internally and verifies the signature against the decoded payload bytes.
              </p>
              <p className="text-sm font-medium mb-2">Request body:</p>
              <pre className="bg-black/30 rounded p-4 text-sm font-mono mb-4">{`{
  "ciphertext": "v1:...",
  "payload": "7b226964223a226576745f74657374227d",
  "signature": "2f6d2a0c9f8f1e0f...",
  "algorithm": "hmac-sha256"
}`}</pre>
              <p className="text-sm font-medium mb-2">Response:</p>
              <pre className="bg-black/30 rounded p-4 text-sm font-mono mb-4">{`{ "verified": true }`}</pre>
              <ul className="text-[var(--text-muted)] text-sm space-y-1">
                <li><code className="bg-black/30 px-1 rounded">payload</code> must be hex-encoded bytes.</li>
                <li><code className="bg-black/30 px-1 rounded">signature</code> must be hex-encoded bytes.</li>
                <li>Supported algorithms: <code className="bg-black/30 px-1 rounded">hmac-sha1</code>, <code className="bg-black/30 px-1 rounded">hmac-sha256</code>, <code className="bg-black/30 px-1 rounded">hmac-sha512</code> (also <code className="bg-black/30 px-1 rounded">sha1</code>, <code className="bg-black/30 px-1 rounded">sha256</code>, <code className="bg-black/30 px-1 rounded">sha512</code> aliases).</li>
              </ul>
            </div>
          </div>

          <div className="border border-[var(--border)] rounded-lg overflow-hidden bg-[var(--surface-elevated)]">
            <div className="px-5 py-3 border-b border-[var(--border)] flex items-center gap-3">
              <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-green-500/20 text-green-400">POST</span>
              <code className="font-mono text-sm">/v1/{`{key_name}`}/proxy-substitute</code>
            </div>
            <div className="p-5">
              <p className="text-[var(--text-muted)] text-sm mb-4">
                Decrypt ciphertext internally, substitute plaintext into a placeholder token inside an outbound request, then return the upstream response.
              </p>
              <p className="text-sm font-medium mb-2">Request body:</p>
              <pre className="bg-black/30 rounded p-4 text-sm font-mono mb-4">{`{
  "ciphertext": "v1:...",
  "placeholder": "{{SIMPLEVAULT_PLAINTEXT}}",
  "request": {
    "method": "POST",
    "url": "https://api.stripe.com/v1/customers/{{SIMPLEVAULT_PLAINTEXT}}",
    "headers": {
      "authorization": "Bearer {{SIMPLEVAULT_PLAINTEXT}}",
      "content-type": "application/json"
    },
    "body": "{\"token\":\"{{SIMPLEVAULT_PLAINTEXT}}\"}"
  }
}`}</pre>
              <p className="text-sm font-medium mb-2">Response:</p>
              <pre className="bg-black/30 rounded p-4 text-sm font-mono">{`{
  "status": 200,
  "headers": { "content-type": "application/json" },
  "body": "{...upstream response body...}"
}`}</pre>
            </div>
          </div>

          <div className="border border-[var(--border)] rounded-lg overflow-hidden bg-[var(--surface-elevated)]">
            <div className="px-5 py-3 border-b border-[var(--border)] flex items-center gap-3">
              <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-green-500/20 text-green-400">POST</span>
              <code className="font-mono text-sm">/v1/{`{key_name}`}/db-query</code>
            </div>
            <div className="p-5">
              <p className="text-[var(--text-muted)] text-sm mb-4">
                Decrypt ciphertext internally to a Postgres connection string, reuse a connection pool keyed by the SHA-256 hash of that string, run a query, and return tabular JSON results.
              </p>
              <p className="text-[var(--text-muted)] text-sm mb-4">
                Single-statement read and write queries are supported. Read queries return rows/columns; write queries (for example <code className="bg-black/30 px-1 rounded">create</code>, <code className="bg-black/30 px-1 rounded">insert</code>, <code className="bg-black/30 px-1 rounded">update</code>, <code className="bg-black/30 px-1 rounded">delete</code>) return <code className="bg-black/30 px-1 rounded">row_count</code> as affected rows with empty <code className="bg-black/30 px-1 rounded">rows</code>/<code className="bg-black/30 px-1 rounded">columns</code>.
              </p>
              <p className="text-[var(--text-muted)] text-sm mb-4">
                Pool entries are evicted after 60 seconds of inactivity. If <code className="bg-black/30 px-1 rounded">db_destinations</code> is configured for the key set, the host/port must match the allowlist.
              </p>
              <p className="text-[var(--text-muted)] text-sm mb-4">
                DB destination rules can also restrict query type with <code className="bg-black/30 px-1 rounded">access</code>. With <code className="bg-black/30 px-1 rounded">read_only</code>, read queries are allowed while write statements are rejected with <code className="bg-black/30 px-1 rounded">403</code>.
              </p>
              <p className="text-sm font-medium mb-2">Request body:</p>
              <pre className="bg-black/30 rounded p-4 text-sm font-mono mb-4">{`{
  "ciphertext": "v1:...",
  "query": {
    "sql": "select id, email from users where id = $1",
    "params": [123]
  },
  "options": {
    "timeout_ms": 5000,
    "max_rows": 500
  }
}`}</pre>
              <p className="text-[var(--text-muted)] text-sm mb-4">
                Params support primitive values (<code className="bg-black/30 px-1 rounded">null</code>, <code className="bg-black/30 px-1 rounded">boolean</code>, <code className="bg-black/30 px-1 rounded">number</code>, <code className="bg-black/30 px-1 rounded">string</code>) and typed objects for explicit binding:
              </p>
              <pre className="bg-black/30 rounded p-4 text-sm font-mono mb-4">{`{
  "query": {
    "sql": "select $1::jsonb->>'kind' as kind, $2::varchar as label",
    "params": [
      { "param_type": "jsonb", "value": { "kind": "customer" } },
      { "param_type": "varchar", "value": "gold" }
    ]
  }
}`}</pre>
              <p className="text-[var(--text-muted)] text-sm mb-4">
                Plain JSON objects/arrays are also accepted as JSON params (for example <code className="bg-black/30 px-1 rounded">{`{"kind":"customer"}`}</code> or <code className="bg-black/30 px-1 rounded">[1,2,3]</code>). Only objects that exactly match <code className="bg-black/30 px-1 rounded">{`{"param_type":"...","value":...}`}</code> use typed binding mode.
              </p>
              <p className="text-[var(--text-muted)] text-sm mb-4">
                Common typed aliases include <code className="bg-black/30 px-1 rounded">bool</code>, <code className="bg-black/30 px-1 rounded">int2</code>, <code className="bg-black/30 px-1 rounded">int4</code>, <code className="bg-black/30 px-1 rounded">int8</code>, <code className="bg-black/30 px-1 rounded">float8</code>, <code className="bg-black/30 px-1 rounded">text</code>, <code className="bg-black/30 px-1 rounded">varchar</code>, <code className="bg-black/30 px-1 rounded">timestamptz</code>, <code className="bg-black/30 px-1 rounded">timestamp</code>, <code className="bg-black/30 px-1 rounded">date</code>, <code className="bg-black/30 px-1 rounded">time</code>, <code className="bg-black/30 px-1 rounded">uuid</code>, <code className="bg-black/30 px-1 rounded">bytea</code>, <code className="bg-black/30 px-1 rounded">json</code>, and <code className="bg-black/30 px-1 rounded">jsonb</code>. For <code className="bg-black/30 px-1 rounded">timestamptz</code>, pass an RFC3339 string.
              </p>
              <p className="text-sm font-medium mb-2">Response:</p>
              <pre className="bg-black/30 rounded p-4 text-sm font-mono">{`{
  "columns": [{ "name": "id" }, { "name": "email" }],
  "rows": [[123, "a@example.com"]],
  "row_count": 1,
  "truncated": false,
  "timing_ms": 18
}`}</pre>
            </div>
          </div>

          <div className="border border-[var(--border)] rounded-lg overflow-hidden bg-[var(--surface-elevated)]">
            <div className="px-5 py-3 border-b border-[var(--border)] flex items-center gap-3">
              <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-blue-500/20 text-blue-400">GET</span>
              <code className="font-mono text-sm">/v1/{`{key_name}`}/version</code>
            </div>
            <div className="p-5">
              <p className="text-[var(--text-muted)] text-sm mb-4">
                Return the latest key version number for the given key name.
              </p>
              <p className="text-sm font-medium mb-2">Response:</p>
              <pre className="bg-black/30 rounded p-4 text-sm font-mono">{`{ "version": 2 }`}</pre>
            </div>
          </div>
        </div>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Error Responses</h2>
        <p className="text-[var(--text-muted)] mb-4">
          Errors return JSON with an <code className="bg-black/30 px-1 rounded">error</code> field:
        </p>
        <ul className="text-[var(--text-muted)] space-y-2">
          <li><code className="bg-black/30 px-1 rounded">401</code> — Missing or invalid API key</li>
          <li><code className="bg-black/30 px-1 rounded">403</code> — API key does not have scope for the key name or operation</li>
          <li><code className="bg-black/30 px-1 rounded">404</code> — Unknown route</li>
          <li><code className="bg-black/30 px-1 rounded">405</code> — Wrong HTTP method</li>
          <li><code className="bg-black/30 px-1 rounded">422</code> — Invalid request body (e.g. missing plaintext, malformed ciphertext, non-hex payload, invalid outbound URL, invalid DB query/DSN)</li>
          <li><code className="bg-black/30 px-1 rounded">500</code> — Server error (e.g. key not found, decryption failed)</li>
          <li><code className="bg-black/30 px-1 rounded">502</code> — Upstream request failed for proxy-substitute</li>
        </ul>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Stripe Webhook Example</h2>
        <p className="text-[var(--text-muted)] mb-3">
          One pattern is to store the Stripe webhook secret encrypted in SimpleVault, generate signatures with <code className="bg-black/30 px-1 rounded">/create-signature</code>, and compare or validate with <code className="bg-black/30 px-1 rounded">/verify-signature</code>.
        </p>
        <ol className="text-[var(--text-muted)] text-sm space-y-2 list-decimal list-inside">
          <li>Encrypt and store your webhook secret once using <code className="bg-black/30 px-1 rounded">/encrypt</code>.</li>
          <li>At webhook time, build the Stripe signed payload string (for example <code className="bg-black/30 px-1 rounded">"{`{timestamp}`}.{`{rawBody}`}"</code> for <code className="bg-black/30 px-1 rounded">v1</code>).</li>
          <li>Hex-encode that payload string and the received <code className="bg-black/30 px-1 rounded">v1</code> signature.</li>
          <li>Call <code className="bg-black/30 px-1 rounded">/verify-signature</code> with <code className="bg-black/30 px-1 rounded">algorithm: "hmac-sha256"</code>.</li>
          <li>Accept only when <code className="bg-black/30 px-1 rounded">verified</code> is <code className="bg-black/30 px-1 rounded">true</code>.</li>
        </ol>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Ciphertext Format</h2>
        <p className="text-[var(--text-muted)] mb-2">
          Ciphertext strings use the format:
        </p>
        <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 text-sm font-mono">
          {`v1:<hex_ciphertext>:<hex_nonce>`}
        </pre>
        <p className="text-[var(--text-muted)] text-sm mt-2">
          Encryption uses AES-256-GCM. The key version is embedded so the server knows which key to use for decryption.
        </p>
      </section>
    </article>
  );
}
