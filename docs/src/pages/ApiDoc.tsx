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
          <li><code className="bg-black/30 px-1 rounded">404</code> — Unknown route</li>
          <li><code className="bg-black/30 px-1 rounded">405</code> — Wrong HTTP method</li>
          <li><code className="bg-black/30 px-1 rounded">422</code> — Invalid request body (e.g. missing plaintext, malformed ciphertext)</li>
          <li><code className="bg-black/30 px-1 rounded">500</code> — Server error (e.g. key not found, decryption failed)</li>
        </ul>
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
