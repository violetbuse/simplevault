export default function ConfigDoc() {
  return (
    <article className="prose prose-invert max-w-none">
      <h1 className="text-3xl font-bold mb-2">Configuration File</h1>
      <p className="text-[var(--text-muted)] mb-8">
        The SimpleVault server is configured via a JSON file or an environment variable passed at startup (raw JSON or base64-encoded JSON).
      </p>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Structure</h2>
        <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 sm:p-6 overflow-x-auto text-sm font-mono">
{`{
  "api_keys": [
    { "value": "secret", "keys": "all", "operations": "all" }
  ],
  "server_port": 8080,
  "keys": {
    "vault": {
      "1": "64-char-hex-key",
      "2": "64-char-hex-key"
    }
  },
  "outbound_destinations": {
    "vault": [
      { "host": "api.stripe.com", "path_prefix": "/v1/", "methods": ["POST"] }
    ]
  },
  "db_destinations": {
    "vault": [
      { "host": "db.internal", "port": 5432, "access": "read_only" }
    ]
  }
}`}
        </pre>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Fields</h2>

        <div className="space-y-6">
          <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--surface-elevated)]">
            <h3 className="font-mono font-semibold text-[var(--accent)] mb-2">api_keys</h3>
            <p className="text-[var(--text-muted)] text-sm mb-2">
              Array of API key entries. Each entry is either a <strong>string</strong> (legacy) or an <strong>object</strong> with <code className="bg-black/30 px-1 rounded">value</code>, <code className="bg-black/30 px-1 rounded">keys</code>, and <code className="bg-black/30 px-1 rounded">operations</code>.
            </p>
            <ul className="text-sm text-[var(--text-muted)] list-disc list-inside space-y-1 mb-3">
              <li>If empty <code className="bg-black/30 px-1 rounded">[]</code>, no authentication is required</li>
              <li>If non-empty, requests to <code className="bg-black/30 px-1 rounded">/encrypt</code>, <code className="bg-black/30 px-1 rounded">/decrypt</code>, <code className="bg-black/30 px-1 rounded">/rotate</code>, <code className="bg-black/30 px-1 rounded">/create-signature</code>, <code className="bg-black/30 px-1 rounded">/verify-signature</code>, <code className="bg-black/30 px-1 rounded">/proxy-substitute</code>, and <code className="bg-black/30 px-1 rounded">/db-query</code> must include a valid key and the key must be allowed for that key name and operation</li>
            </ul>
            <p className="text-sm text-[var(--text-muted)] mb-2 font-medium">Object form (per entry):</p>
            <ul className="text-sm text-[var(--text-muted)] list-disc list-inside space-y-1">
              <li><code className="bg-black/30 px-1 rounded">value</code> (required) — The secret key string used to authenticate (e.g. Bearer token, <code className="bg-black/30 px-1 rounded">x-api-key</code> header)</li>
              <li><code className="bg-black/30 px-1 rounded">keys</code> (optional, default <code className="bg-black/30 px-1 rounded">"all"</code>) — Either the string <code className="bg-black/30 px-1 rounded">"all"</code> or an array of key set names (e.g. <code className="bg-black/30 px-1 rounded">["vault", "other"]</code>) this API key can access</li>
              <li><code className="bg-black/30 px-1 rounded">operations</code> (optional, default <code className="bg-black/30 px-1 rounded">"all"</code>) — Either the string <code className="bg-black/30 px-1 rounded">"all"</code> or an array of allowed operations: <code className="bg-black/30 px-1 rounded">["encrypt", "decrypt", "rotate", "verify", "sign", "proxy", "db_query"]</code></li>
            </ul>
            <p className="text-sm text-[var(--text-muted)] mt-2">
              <strong>Backwards compatible:</strong> a plain string (e.g. <code className="bg-black/30 px-1 rounded">"my-key"</code>) is treated as <code className="bg-black/30 px-1 rounded">keys: "all"</code> and <code className="bg-black/30 px-1 rounded">operations: "all"</code>.
            </p>
          </div>

          <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--surface-elevated)]">
            <h3 className="font-mono font-semibold text-[var(--accent)] mb-2">server_port</h3>
            <p className="text-[var(--text-muted)] text-sm">
              Port number (u16) the HTTP server listens on. Default is typically 8080. Can be overridden at runtime with <code className="bg-black/30 px-1 rounded">--port</code> / <code className="bg-black/30 px-1 rounded">-p</code>.
            </p>
          </div>

          <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--surface-elevated)]">
            <h3 className="font-mono font-semibold text-[var(--accent)] mb-2">keys</h3>
            <p className="text-[var(--text-muted)] text-sm mb-2">
              Object mapping key names to versioned encryption keys. Each key name (e.g. <code className="bg-black/30 px-1 rounded">vault</code>) maps to an object of version → hex key.
            </p>
            <ul className="text-sm text-[var(--text-muted)] list-disc list-inside space-y-1">
              <li>Version numbers are integers (1, 2, 3, …)</li>
              <li>Each key must be exactly 64 hex characters (256-bit AES key)</li>
              <li>Multiple versions allow key rotation while decrypting old ciphertext</li>
            </ul>
          </div>

          <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--surface-elevated)]">
            <h3 className="font-mono font-semibold text-[var(--accent)] mb-2">outbound_destinations</h3>
            <p className="text-[var(--text-muted)] text-sm mb-2">
              Optional map of key set name to outbound destination allowlist rules for <code className="bg-black/30 px-1 rounded">proxy-substitute</code>.
            </p>
            <ul className="text-sm text-[var(--text-muted)] list-disc list-inside space-y-1">
              <li>Key is the key set name (for example <code className="bg-black/30 px-1 rounded">vault</code>)</li>
              <li>Each rule requires <code className="bg-black/30 px-1 rounded">host</code> and may include <code className="bg-black/30 px-1 rounded">path_prefix</code> and <code className="bg-black/30 px-1 rounded">methods</code></li>
              <li>If this object is missing, destinations are allowed by default</li>
            </ul>
          </div>

          <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--surface-elevated)]">
            <h3 className="font-mono font-semibold text-[var(--accent)] mb-2">db_destinations</h3>
            <p className="text-[var(--text-muted)] text-sm mb-2">
              Optional map of key set name to DB destination allowlist rules for <code className="bg-black/30 px-1 rounded">db-query</code>.
            </p>
            <ul className="text-sm text-[var(--text-muted)] list-disc list-inside space-y-1">
              <li>Key is the key set name (for example <code className="bg-black/30 px-1 rounded">vault</code>)</li>
              <li>Each rule requires <code className="bg-black/30 px-1 rounded">host</code> and may include <code className="bg-black/30 px-1 rounded">port</code></li>
              <li>Each rule may include <code className="bg-black/30 px-1 rounded">access</code>: <code className="bg-black/30 px-1 rounded">"read_only"</code> or <code className="bg-black/30 px-1 rounded">"read_write"</code> (default)</li>
              <li><code className="bg-black/30 px-1 rounded">read_only</code> allows SELECT/CTE/VALUES style reads only; write statements like CREATE/INSERT/UPDATE/DELETE are blocked</li>
              <li>If this object is missing, DB destinations are allowed by default</li>
              <li>If the key set exists with an empty rule list, all DB destinations are denied for that key set</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Example</h2>
        <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 sm:p-6 overflow-x-auto text-sm font-mono">
{`{
  "api_keys": [
    { "value": "1234567890", "keys": "all", "operations": "all" }
  ],
  "server_port": 8080,
  "keys": {
    "vault": {
      "1": "0000000000000000000000000000000000000000000000000000000000000000",
      "2": "1111111111111111111111111111111111111111111111111111111111111111"
    }
  },
  "outbound_destinations": {
    "vault": [
      { "host": "api.stripe.com", "path_prefix": "/v1/", "methods": ["POST"] }
    ]
  },
  "db_destinations": {
    "vault": [
      { "host": "db.internal", "port": 5432, "access": "read_only" },
      { "host": "db.internal", "port": 5432, "access": "read_write" }
    ]
  }
}`}
        </pre>
        <p className="text-sm text-[var(--text-muted)] mt-2">
          To restrict a key to specific key sets or operations, use e.g. <code className="bg-black/30 px-1 rounded">"keys": ["vault"]</code> or <code className="bg-black/30 px-1 rounded">"operations": ["encrypt", "decrypt"]</code>.
        </p>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Usage</h2>
        <p className="text-[var(--text-muted)] mb-4">
          Pre-built binaries are available on <a href="https://github.com/violetbuse/simplevault/releases" target="_blank" rel="noopener noreferrer" className="text-[var(--accent)] hover:underline">GitHub Releases</a>. Config can be read from a file or from an environment variable. By default, the config source (file or env var) is deleted/unset after reading for security. Use <code className="bg-black/30 px-1 rounded">--keep-config</code> to retain it.
        </p>

        <h3 className="font-semibold mb-2 text-[var(--accent)]">CLI options</h3>
        <ul className="text-sm text-[var(--text-muted)] list-disc list-inside space-y-1 mb-4">
          <li><code className="bg-black/30 px-1 rounded">--port</code> / <code className="bg-black/30 px-1 rounded">-p</code> — Port to listen on (overrides <code className="bg-black/30 px-1 rounded">server_port</code> from config)</li>
        </ul>

        <h3 className="font-semibold mb-2 text-[var(--accent)]">From file</h3>
        <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 sm:p-6 overflow-x-auto text-sm font-mono mb-4">
{`simplevault config.json
simplevault --keep-config config.json
simplevault config.json --port 3000`}
        </pre>

        <h3 className="font-semibold mb-2 text-[var(--accent)]">From environment variable</h3>
        <p className="text-[var(--text-muted)] mb-2 text-sm">
          The env var may contain the same JSON as the file, or base64-encoded JSON (standard alphabet). Raw JSON is parsed first; if that fails, the value is decoded as base64 then parsed as JSON. Use the Config Maker to export as JSON or Base64.
        </p>
        <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 sm:p-6 overflow-x-auto text-sm font-mono mb-4">
{`simplevault --config-env SIMPLEVAULT_CONFIG
simplevault --config-env SIMPLEVAULT_CONFIG --keep-config`}
        </pre>

        <h3 className="font-semibold mb-2 text-[var(--accent)]">Delete file and env var</h3>
        <p className="text-[var(--text-muted)] mb-2 text-sm">
          When reading from file, use <code className="bg-black/30 px-1 rounded">--delete-env VAR</code> to also unset an environment variable after reading (e.g. a backup copy of the config).
        </p>
        <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 sm:p-6 overflow-x-auto text-sm font-mono">
{`simplevault config.json --delete-env SIMPLEVAULT_CONFIG_BACKUP`}
        </pre>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Docker</h2>
        <p className="text-[var(--text-muted)] mb-4">
          The Docker image expects config via the <code className="bg-black/30 px-1 rounded">SIMPLEVAULT_CONFIG</code> environment variable (raw JSON or base64-encoded JSON). Use the Config Maker to export your config as JSON or Base64.
        </p>

        <h3 className="font-semibold mb-2 text-[var(--accent)]">Basic run</h3>
        <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 sm:p-6 overflow-x-auto text-sm font-mono mb-4">
{`docker run -e SIMPLEVAULT_CONFIG="<base64>" -p 8080:8080 simplevault`}
        </pre>

        <h3 className="font-semibold mb-2 text-[var(--accent)]">Custom port</h3>
        <p className="text-[var(--text-muted)] mb-2 text-sm">
          Use <code className="bg-black/30 px-1 rounded">--port</code> to listen on a different port inside the container, then map it with Docker&apos;s <code className="bg-black/30 px-1 rounded">-p</code>.
        </p>
        <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 sm:p-6 overflow-x-auto text-sm font-mono mb-4">
{`docker run -e SIMPLEVAULT_CONFIG="<base64>" -p 3000:3000 simplevault --config-env SIMPLEVAULT_CONFIG --port 3000`}
        </pre>

        <h3 className="font-semibold mb-2 text-[var(--accent)]">Mounted config file</h3>
        <p className="text-[var(--text-muted)] mb-2 text-sm">
          Alternatively, mount a config file and pass its path.
        </p>
        <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 sm:p-6 overflow-x-auto text-sm font-mono">
{`docker run -v /path/to/config.json:/app/config.json -p 8080:8080 simplevault /app/config.json`}
        </pre>
      </section>
    </article>
  );
}
