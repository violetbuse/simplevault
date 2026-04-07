export default function DevDoc() {
  return (
    <article className="prose prose-invert max-w-none">
      <h1 className="text-3xl font-bold mb-2">JavaScript client</h1>
      <p className="text-[var(--text-muted)] mb-8">
        The npm package <code className="bg-black/30 px-1 rounded">simplevault</code> is an HTTP client for the SimpleVault API. For local development, run the official Rust server binary and point the client at it; there is no JavaScript implementation of the server.
      </p>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Recommended: Rust binary + npm client</h2>
        <ol className="text-[var(--text-muted)] text-sm space-y-3 list-decimal list-inside">
          <li>
            Install or build the server: use{" "}
            <a href="/" className="text-[var(--accent)] hover:underline">
              the install script
            </a>{" "}
            from the home page, download a release from{" "}
            <a href="https://github.com/violetbuse/simplevault/releases" target="_blank" rel="noopener noreferrer" className="text-[var(--accent)] hover:underline">
              GitHub Releases
            </a>
            , or from the repo root run{" "}
            <code className="bg-black/30 px-1 rounded">cargo run --release -- config.json</code> (or{" "}
            <code className="bg-black/30 px-1 rounded">--config-env …</code>
            ).
          </li>
          <li>
            Start the server on a known port (default from config or{" "}
            <code className="bg-black/30 px-1 rounded">--port</code>
            ).
          </li>
          <li>
            <code className="bg-black/30 px-1 rounded">npm install simplevault</code> and set{" "}
            <code className="bg-black/30 px-1 rounded">baseUrl</code> to that server (e.g.{" "}
            <code className="bg-black/30 px-1 rounded">http://localhost:8080</code>
            ).
          </li>
        </ol>
        <p className="text-[var(--text-muted)] text-sm mt-4">
          Config format, Docker, and security options are covered on the{" "}
          <a href="/config" className="text-[var(--accent)] hover:underline">
            Config
          </a>{" "}
          page.
        </p>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Installation</h2>
        <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 sm:p-6 overflow-x-auto text-sm font-mono">
{`npm install simplevault`}
        </pre>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Client library</h2>
        <p className="text-[var(--text-muted)] mb-4">
          Use <code className="bg-black/30 px-1 rounded">SimpleVaultClient</code> to encrypt, decrypt, rotate keys, proxy-substitute, db-query, signatures, and version.
        </p>
        <pre className="bg-[var(--surface-elevated)] border border-[var(--border)] rounded-lg p-4 sm:p-6 overflow-x-auto text-sm font-mono mb-4">
{`import { SimpleVaultClient } from 'simplevault';

const client = new SimpleVaultClient({
  baseUrl: 'http://localhost:8080',
  apiKey: 'optional-key',  // omit if server has no api_keys
});

const { ciphertext } = await client.encrypt('vault', 'secret message');
const { plaintext } = await client.decrypt('vault', ciphertext);
const { ciphertext: rotated } = await client.rotate('vault', ciphertext);
const { version } = await client.getVersion('vault');`}
        </pre>
        <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--surface-elevated)]">
          <h3 className="font-mono font-semibold text-[var(--accent)] mb-2">SimpleVaultClientOptions</h3>
          <ul className="text-sm text-[var(--text-muted)] list-disc list-inside space-y-1">
            <li><code className="bg-black/30 px-1 rounded">baseUrl</code> — Base URL of the SimpleVault server</li>
            <li><code className="bg-black/30 px-1 rounded">apiKey</code> — Optional; Bearer and x-api-key when the server requires auth</li>
          </ul>
        </div>
      </section>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Rust client library</h2>
        <p className="text-[var(--text-muted)] mb-4">
          The Rust crate includes a transport-backed client in <code className="bg-black/30 px-1 rounded">simplevault::client</code> with HTTP and in-memory transports for tests.
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
          For tests without HTTP, use <code className="bg-black/30 px-1 rounded">InMemoryTransport</code> with{" "}
          <code className="bg-black/30 px-1 rounded">api::build_router(config)</code>.
        </p>
      </section>
    </article>
  );
}
