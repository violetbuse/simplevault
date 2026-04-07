# simplevault

Node.js HTTP client for [SimpleVault](https://github.com/violetbuse/simplevault) — a minimal encryption API using AES-256-GCM.

There is **no** JavaScript server in this package. For local development, run the **Rust** `simplevault` binary (see the main repo [README](https://github.com/violetbuse/simplevault) and [documentation](https://simplevault.viowet.com): install script, GitHub Releases, Docker, or `cargo run`), then point this client at that URL.

## Installation

```bash
npm install simplevault
```

## Client library

```typescript
import { SimpleVaultClient } from 'simplevault';

const client = new SimpleVaultClient({
  baseUrl: 'http://localhost:8080',
  apiKey: 'optional-key', // omit if server has no api_keys
});

const { ciphertext } = await client.encrypt('vault', 'secret message');
const { plaintext } = await client.decrypt('vault', ciphertext);
const { ciphertext: rotated } = await client.rotate('vault', ciphertext);
const { version } = await client.getVersion('vault');

const result = await client.dbQuery('vault', {
  ciphertext,
  query: {
    sql: 'select $1::int as n, $2::text as label, $3::text is null as is_null',
    params: [
      { type: 'int4', value: 123 },
      { type: 'text', value: 'gold' },
      { type: 'null', value: null },
    ],
  },
});
```

## Contract tests

From the **repository root**, build the release binary, then from `client/`:

```bash
npm ci
npm run build
node test/run-with-rust-server.mjs
```

Or with a server already running:

```bash
SIMPLEVAULT_BASE_URL=http://localhost:8080 npm run test:contract
```

## License

MIT
