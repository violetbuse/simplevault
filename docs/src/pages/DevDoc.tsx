export default function DevDoc() {
  return (
    <article className="prose prose-invert max-w-none">
      <h1 className="text-3xl font-bold mb-2">Client & Dev Server</h1>
      <p className="text-[var(--text-muted)] mb-8">
        The SimpleVault npm package provides a Node.js client library and a local dev server that emulates the full SimpleVault API for development.
      </p>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Installation</h2>
        <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 sm:p-6 overflow-x-auto text-sm font-mono">
{`npm install simplevault`}
        </pre>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Client Library</h2>
        <p className="text-[var(--text-muted)] mb-4">
          Use <code className="bg-black/30 px-1 rounded">SimpleVaultClient</code> to encrypt, decrypt, rotate keys, and get version info.
        </p>
        <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 sm:p-6 overflow-x-auto text-sm font-mono mb-4">
{`import { SimpleVaultClient } from 'simplevault';

const client = new SimpleVaultClient({
  baseUrl: 'http://localhost:8080',
  apiKey: 'optional-key',  // omit if server has no api_keys
});

// Encrypt
const { ciphertext } = await client.encrypt('vault', 'secret message');

// Decrypt
const { plaintext } = await client.decrypt('vault', ciphertext);

// Key rotation (re-encrypt with latest key)
const { ciphertext: rotated } = await client.rotate('vault', ciphertext);

// Get latest key version
const { version } = await client.getVersion('vault');`}
        </pre>
        <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--surface-elevated)]">
          <h3 className="font-mono font-semibold text-[var(--accent)] mb-2">SimpleVaultClientOptions</h3>
          <ul className="text-sm text-[var(--text-muted)] list-disc list-inside space-y-1">
            <li><code className="bg-black/30 px-1 rounded">baseUrl</code> — Base URL of the SimpleVault server (e.g. <code className="bg-black/30 px-1 rounded">http://localhost:8080</code>)</li>
            <li><code className="bg-black/30 px-1 rounded">apiKey</code> — Optional. Used as Bearer token and x-api-key header when the server requires authentication</li>
          </ul>
        </div>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Rust Client Library</h2>
        <p className="text-[var(--text-muted)] mb-4">
          The Rust crate now includes a transport-backed client in <code className="bg-black/30 px-1 rounded">simplevault::client</code>.
          It supports a real HTTP transport and an in-memory Axum transport for tests.
        </p>
        <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 sm:p-6 overflow-x-auto text-sm font-mono mb-4">
{`use simplevault::client::{HttpTransport, SimpleVaultClient};

let transport = HttpTransport::new("http://localhost:8080", Some("api-key".to_string()));
let client = SimpleVaultClient::new("vault", transport);

let encrypted = client.encrypt("secret").await?;
let decrypted = client.decrypt(encrypted.ciphertext).await?;
assert_eq!(decrypted.plaintext, "secret");`}
        </pre>
        <p className="text-[var(--text-muted)]">
          For serverless tests, use <code className="bg-black/30 px-1 rounded">InMemoryTransport</code> with
          <code className="bg-black/30 px-1 rounded"> api::build_router(config)</code> to run requests directly against the router.
        </p>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">CLI</h2>
        <p className="text-[var(--text-muted)] mb-4">
          The <code className="bg-black/30 px-1 rounded">simplevault</code> CLI provides two commands: <code className="bg-black/30 px-1 rounded">dev</code> (default) and <code className="bg-black/30 px-1 rounded">init</code>.
        </p>

        <div className="space-y-6 mb-6">
          <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--surface-elevated)]">
            <h3 className="font-mono font-semibold text-[var(--accent)] mb-2">dev</h3>
            <p className="text-[var(--text-muted)] text-sm mb-3">
              Start the dev server. Emulates the full SimpleVault API with simplified config. Watches the config file and restarts on change.
            </p>
            <p className="text-amber-400/90 text-sm mb-2 font-medium">
              WARNING: For local development only. Do not use in production.
            </p>
            <pre className="bg-black/30 rounded-lg p-3 overflow-x-auto text-sm font-mono">
{`npx simplevault
npx simplevault dev

# Custom port
npx simplevault dev -p 3000
npx simplevault dev --port 3000

# Custom config path
npx simplevault dev -c ./my-config.json
npx simplevault dev --config ./my-config.json`}
            </pre>
            <ul className="text-sm text-[var(--text-muted)] list-disc list-inside space-y-1 mt-2">
              <li><code className="bg-black/30 px-1 rounded">-p, --port &lt;number&gt;</code> — Port to listen on (default: 8080)</li>
              <li><code className="bg-black/30 px-1 rounded">-c, --config &lt;path&gt;</code> — Path to config JSON (default: simplevault.config.json)</li>
            </ul>
          </div>

          <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--surface-elevated)]">
            <h3 className="font-mono font-semibold text-[var(--accent)] mb-2">init</h3>
            <p className="text-[var(--text-muted)] text-sm mb-3">
              Create a default config file with a sample vault key.
            </p>
            <pre className="bg-black/30 rounded-lg p-3 overflow-x-auto text-sm font-mono">
{`npx simplevault init
npx simplevault init -o ./my-config.json
npx simplevault init --output ./my-config.json`}
            </pre>
            <ul className="text-sm text-[var(--text-muted)] list-disc list-inside space-y-1 mt-2">
              <li><code className="bg-black/30 px-1 rounded">-o, --output &lt;path&gt;</code> — Output path (default: simplevault.config.json)</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Dev Config Format</h2>
        <p className="text-[var(--text-muted)] mb-4">
          The dev server uses the same structure as the Rust server config, but without delete-after, env vars, or other security features.
        </p>
        <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 sm:p-6 overflow-x-auto text-sm font-mono mb-4">
{`{
  "api_keys": [],
  "server_port": 8080,
  "keys": {
    "vault": {
      "1": "64-char-hex-aes-key",
      "2": "64-char-hex-aes-key"
    }
  }
}`}
        </pre>
        <ul className="text-sm text-[var(--text-muted)] list-disc list-inside space-y-1">
          <li><code className="bg-black/30 px-1 rounded">api_keys</code> — Empty = no auth; non-empty = require Bearer / x-api-key / ?api_key=</li>
          <li><code className="bg-black/30 px-1 rounded">server_port</code> — Port (overridden by <code className="bg-black/30 px-1 rounded">-p</code> when using the CLI)</li>
          <li><code className="bg-black/30 px-1 rounded">keys</code> — Key name → version → 64-char hex (256-bit AES key)</li>
        </ul>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">API Compatibility</h2>
        <p className="text-[var(--text-muted)]">
          The dev server is compatible with the Rust SimpleVault service. Ciphertext produced by one can be decrypted by the other when using the same keys.
        </p>
      </section>
    </article>
  );
}
