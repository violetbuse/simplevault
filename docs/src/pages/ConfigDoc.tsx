export default function ConfigDoc() {
  return (
    <article className="prose prose-invert max-w-none">
      <h1 className="text-3xl font-bold mb-2">Configuration File</h1>
      <p className="text-[var(--text-muted)] mb-8">
        The SimpleVault server is configured via a JSON file passed at startup.
      </p>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Structure</h2>
        <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 sm:p-6 overflow-x-auto text-sm font-mono">
{`{
  "api_keys": ["key1", "key2"],
  "server_port": 8080,
  "keys": {
    "vault": {
      "1": "64-char-hex-key",
      "2": "64-char-hex-key"
    }
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
              Array of strings. API keys used to authenticate requests.
            </p>
            <ul className="text-sm text-[var(--text-muted)] list-disc list-inside space-y-1">
              <li>If empty <code className="bg-black/30 px-1 rounded">[]</code>, no authentication is required</li>
              <li>If non-empty, all API requests must include a valid key</li>
            </ul>
          </div>

          <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--surface-elevated)]">
            <h3 className="font-mono font-semibold text-[var(--accent)] mb-2">server_port</h3>
            <p className="text-[var(--text-muted)] text-sm">
              Port number (u16) the HTTP server listens on. Default is typically 8080.
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
        </div>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Example</h2>
        <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 sm:p-6 overflow-x-auto text-sm font-mono">
{`{
  "api_keys": ["1234567890"],
  "server_port": 8080,
  "keys": {
    "vault": {
      "1": "0000000000000000000000000000000000000000000000000000000000000000",
      "2": "1111111111111111111111111111111111111111111111111111111111111111"
    }
  }
}`}
        </pre>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Usage</h2>
        <p className="text-[var(--text-muted)] mb-4">
          Pass the config path when starting the server. By default, the config file is deleted after reading (for security). Use <code className="bg-black/30 px-1 rounded">--keep-config</code> to retain it.
        </p>
        <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 sm:p-6 overflow-x-auto text-sm font-mono">
{`simplevault config.json
simplevault --keep-config config.json`}
        </pre>
      </section>
    </article>
  );
}
