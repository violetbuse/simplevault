# simplevault

Node.js client library and dev server for [SimpleVault](https://github.com/your-org/simplevault) — a minimal encryption API using AES-256-GCM.

## Installation

```bash
npm install simplevault
```

## Client Library

```typescript
import { SimpleVaultClient } from 'simplevault';

const client = new SimpleVaultClient({
  baseUrl: 'http://localhost:8080',
  apiKey: 'optional-key', // omit if server has no api_keys
});

// Encrypt
const { ciphertext } = await client.encrypt('vault', 'secret message');

// Decrypt
const { plaintext } = await client.decrypt('vault', ciphertext);

// Key rotation (re-encrypt with latest key)
const { ciphertext: rotated } = await client.rotate('vault', ciphertext);

// Get latest key version
const { version } = await client.getVersion('vault');

// DB query typed params (including SQL NULL)
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

## CLI

### init

Create a default config file at `simplevault.config.json` (or a custom path):

```bash
npx simplevault init
npx simplevault init -o ./my-config.json
```

### dev

Start the dev server for local development. Emulates the full SimpleVault API with simplified configuration.

```bash
# Uses simplevault.config.json if present, else built-in defaults
npx simplevault
npx simplevault dev

# Custom port
npx simplevault --port 3000

# Custom config path
npx simplevault --config ./config.json
```

### Config format

```json
{
  "api_keys": [],
  "server_port": 8080,
  "keys": {
    "vault": {
      "1": "64-char-hex-aes-key",
      "2": "64-char-hex-aes-key"
    }
  }
}
```

- `api_keys`: empty = no auth; non-empty = require Bearer / x-api-key / ?api_key=
- `keys`: key name → version → 64-char hex (256-bit AES key)

## API Compatibility

The dev server is compatible with the Rust SimpleVault service. Ciphertext produced by one can be decrypted by the other when using the same keys.

## License

MIT
