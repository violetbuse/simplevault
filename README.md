# SimpleVault

SimpleVault is an HTTP server that encrypts and decrypts data using versioned AES-256-GCM keys. Clients send plaintext or ciphertext to the server; keys never leave the server. Multiple key names and versions are supported for key rotation.

## Documentation

Full documentation is published at [simplevault.viowet.com](https://simplevault.viowet.com). The docs site covers:

- **Configuration** — JSON config (file or base64 env var), `api_keys`, `server_port`, versioned keys (64-char hex). For production secrets, prefer env-based config over mounted files. Options to delete config after reading, override port, and use Docker.
- **Config Maker** — Interactive tool to build config, generate hex keys, and export as JSON or Base64 for env/Docker.
- **API Routes** — `POST /v1/{key_name}/encrypt`, `POST /v1/{key_name}/decrypt`, `POST /v1/{key_name}/rotate`, `GET /v1/{key_name}/version`. Optional API key auth via Bearer, `x-api-key`, or `?api_key=`. Ciphertext format `v<version>:<hex>:<nonce>`.
- **Client & Dev Server** — npm package `simplevault`: `SimpleVaultClient` for Node and a local dev server that emulates the API for development.

## Rust server (this repo)

The server is implemented in Rust in the `src/` directory:

- **`main.rs`** — CLI (clap): config path or `--config-env`, `--port`, `--keep-config`, `--delete-env`. Loads config, then runs the HTTP server.
- **`config.rs`** — Config struct (`api_keys`, `server_port`, versioned keys). Reads from file or from a base64-encoded env var. By default it securely removes the config source after reading, if the runtime user has permission to overwrite and delete the original file. API keys and keys stored in secret types; validation helpers for auth and key lookup.
- **`api.rs`** — Axum router: encrypt, decrypt, rotate, version handlers; auth middleware (Bearer, `x-api-key`, query); JSON request/response with typed errors. Uses Tokio’s multi-threaded runtime.
- **`crypto.rs`** — AES-256-GCM via `aes_gcm`. Encryption keys are 32-byte hex in config. Ciphertext format `v<version>:<hex_ciphertext>:<hex_nonce>`. Plaintext and keys held in `secrecy`’s `SecretSlice` / `SecretBox`; debug impls redact sensitive data.

Config can be removed or unset after startup so it does not remain on disk or in the process environment.

## Client and dev server

The npm package [simplevault](https://www.npmjs.com/package/simplevault) provides a Node.js client (`SimpleVaultClient`) and a CLI dev server (`npx simplevault` or `npx simplevault dev`) that implements the same API for local use. Ciphertext is compatible between the Rust server and the dev server when using the same keys.

## Running the server

- **Install script (Linux x86_64/arm64, macOS Apple Silicon)**: downloads the latest release, installs to `~/.local/bin` by default, and on later runs skips install when already up to date (use `--force` to reinstall).

  ```bash
  curl -fsSL https://raw.githubusercontent.com/violetbuse/simplevault/master/install.sh | bash
  ```

  Options: `--prefix DIR`, `--force`, `--dry-run`. Override repo with `SIMPLEVAULT_INSTALL_REPO=owner/name` or install dir with `SIMPLEVAULT_INSTALL_PREFIX`.

- **Built binaries**: [GitHub Releases](https://github.com/violetbuse/simplevault/releases). Download the archive for your platform and run e.g. `./simplevault config.json`. Intel Macs do not ship a pre-built archive; use Docker, build from source, or the Linux binary via another environment.
- **Docker**: [GitHub Container Registry — simplevault](https://github.com/users/violetbuse/packages/container/package/simplevault). The image runs directly as a non-root user. For production, pass config via `SIMPLEVAULT_CONFIG` (JSON or base64) rather than a mounted config file so the container does not depend on a persistent on-disk secret.
- **From source**: `cargo run -- config.json` or `cargo run -- --config-env SIMPLEVAULT_CONFIG`. Use `--port` to override the port, `--keep-config` to keep the config source after reading. Prefer `--config-env` for production secrets; file-based deletion depends on the runtime user being allowed to overwrite and remove the source file.

See the [documentation](https://simplevault.viowet.com) for detailed configuration, Docker examples, and API usage.

## Links

- Documentation: [simplevault.viowet.com](https://simplevault.viowet.com)
- Releases (built binaries): [GitHub Releases](https://github.com/violetbuse/simplevault/releases)
- Docker image: [GitHub Container Registry](https://github.com/users/violetbuse/packages/container/package/simplevault)
- npm package (client + dev server): [npm — simplevault](https://www.npmjs.com/package/simplevault)
- Source: [github.com/violetbuse/simplevault](https://github.com/violetbuse/simplevault)
