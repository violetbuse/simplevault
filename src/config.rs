use std::{
    collections::HashMap,
    fmt::Debug,
    io::SeekFrom,
    path::{Path, PathBuf},
};

use base64::Engine;

use rand::Rng;
use secrecy::{ExposeSecret, SecretSlice};
use serde::{
    Deserialize,
    de::{Deserializer, Error as SerdeError},
};
use tokio::{
    fs::{File, remove_file},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::EncryptionKey;

#[derive(Debug, Deserialize)]
pub struct Config {
    api_keys: Vec<ApiKey>,
    pub server_port: u16,
    keys: KeySet,
    #[serde(default)]
    outbound_destinations: HashMap<String, Vec<OutboundDestinationRule>>,
    #[serde(default)]
    db_destinations: HashMap<String, Vec<DbDestinationRule>>,
}

impl Config {
    pub fn api_keys_required(&self) -> bool {
        !self.api_keys.is_empty()
    }

    pub fn validate_api_key<T: AsRef<str>>(&self, key: T) -> bool {
        self.api_keys.iter().any(|k| k.matches(key.as_ref()))
    }

    /// Returns the first API key that matches the given key value, for scope checks.
    pub fn get_matching_api_key<T: AsRef<str>>(&self, key: T) -> Option<&ApiKey> {
        self.api_keys.iter().find(|k| k.matches(key.as_ref()))
    }

    pub fn get_key(&self, key_name: &str, version: u32) -> Option<&EncryptionKey> {
        self.keys.get(key_name).and_then(|vk| vk.get(&version))
    }

    pub fn get_latest_key(&self, key_name: &str) -> Option<(u32, &EncryptionKey)> {
        self.keys
            .get(key_name)?
            .iter()
            .max_by_key(|(v, _)| *v)
            .map(|(v, k)| (*v, k))
    }

    pub fn destination_allowed(
        &self,
        key_name: &str,
        method: &str,
        host: &str,
        path: &str,
    ) -> bool {
        let rules = match self.outbound_destinations.get(key_name) {
            Some(value) => value,
            None => return true,
        };
        rules.iter().any(|rule| rule.matches(method, host, path))
    }

    #[cfg(test)]
    pub fn db_destination_allowed(&self, key_name: &str, host: &str, port: u16) -> bool {
        self.db_destination_allows_query(key_name, host, port, false)
    }

    pub fn db_destination_allows_query(
        &self,
        key_name: &str,
        host: &str,
        port: u16,
        requires_write: bool,
    ) -> bool {
        let rules = match self.db_destinations.get(key_name) {
            Some(value) => value,
            None => return true,
        };
        rules
            .iter()
            .any(|rule| rule.host_port_matches(host, port) && rule.allows_query(requires_write))
    }

    #[cfg(test)]
    pub fn api_keys(&self) -> &[ApiKey] {
        &self.api_keys
    }
}

/// Scope for which key names this API key can access: "all" or a list of key names.
#[derive(Clone, Debug, Default)]
pub enum KeysScope {
    #[default]
    All,
    List(Vec<String>),
}

impl KeysScope {
    pub fn allows(&self, key_name: &str) -> bool {
        match self {
            KeysScope::All => true,
            KeysScope::List(names) => names.iter().any(|n| n == key_name),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum KeysScopeInput {
    All(String),
    List(Vec<String>),
}

impl KeysScopeInput {
    fn into_scope(self) -> Result<KeysScope, String> {
        match self {
            KeysScopeInput::All(s) => {
                if s == "all" {
                    Ok(KeysScope::All)
                } else {
                    Err("keys must be the string \"all\" or an array of strings".to_string())
                }
            }
            KeysScopeInput::List(l) => Ok(KeysScope::List(l)),
        }
    }
}

impl<'de> Deserialize<'de> for KeysScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        KeysScopeInput::deserialize(deserializer)?
            .into_scope()
            .map_err(SerdeError::custom)
    }
}

/// Allowed operation: encrypt, decrypt, rotate, verify, sign, or proxy.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyOperation {
    Encrypt,
    Decrypt,
    Rotate,
    Verify,
    Sign,
    Proxy,
    #[serde(rename = "db_query")]
    DbQuery,
}

/// Scope for which operations this API key can perform: "all" or a list of operations.
#[derive(Clone, Debug, Default)]
pub enum OperationsScope {
    #[default]
    All,
    List(Vec<ApiKeyOperation>),
}

impl OperationsScope {
    pub fn allows_encrypt(&self) -> bool {
        match self {
            OperationsScope::All => true,
            OperationsScope::List(ops) => ops.iter().any(|o| matches!(o, ApiKeyOperation::Encrypt)),
        }
    }

    pub fn allows_decrypt(&self) -> bool {
        match self {
            OperationsScope::All => true,
            OperationsScope::List(ops) => ops.iter().any(|o| matches!(o, ApiKeyOperation::Decrypt)),
        }
    }

    pub fn allows_rotate(&self) -> bool {
        match self {
            OperationsScope::All => true,
            OperationsScope::List(ops) => ops.iter().any(|o| matches!(o, ApiKeyOperation::Rotate)),
        }
    }

    pub fn allows_verify(&self) -> bool {
        match self {
            OperationsScope::All => true,
            OperationsScope::List(ops) => ops.iter().any(|o| matches!(o, ApiKeyOperation::Verify)),
        }
    }

    pub fn allows_sign(&self) -> bool {
        match self {
            OperationsScope::All => true,
            OperationsScope::List(ops) => ops.iter().any(|o| matches!(o, ApiKeyOperation::Sign)),
        }
    }

    pub fn allows_proxy(&self) -> bool {
        match self {
            OperationsScope::All => true,
            OperationsScope::List(ops) => ops.iter().any(|o| matches!(o, ApiKeyOperation::Proxy)),
        }
    }

    pub fn allows_db_query(&self) -> bool {
        match self {
            OperationsScope::All => true,
            OperationsScope::List(ops) => ops.iter().any(|o| matches!(o, ApiKeyOperation::DbQuery)),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OperationsScopeInput {
    All(String),
    List(Vec<ApiKeyOperation>),
}

impl OperationsScopeInput {
    fn into_scope(self) -> Result<OperationsScope, String> {
        match self {
            OperationsScopeInput::All(s) => {
                if s == "all" {
                    Ok(OperationsScope::All)
                } else {
                    Err("operations must be the string \"all\" or an array of \"encrypt\", \"decrypt\", \"rotate\", \"verify\", \"sign\", \"proxy\", \"db_query\"".to_string())
                }
            }
            OperationsScopeInput::List(l) => Ok(OperationsScope::List(l)),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct OutboundDestinationRule {
    pub host: String,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub methods: Option<Vec<String>>,
}

impl OutboundDestinationRule {
    fn matches(&self, method: &str, host: &str, path: &str) -> bool {
        let normalized_rule_host = self.host.to_ascii_lowercase();
        let normalized_host = host.to_ascii_lowercase();
        if normalized_rule_host != normalized_host {
            return false;
        }

        if let Some(path_prefix) = &self.path_prefix {
            if !path.starts_with(path_prefix) {
                return false;
            }
        }

        if let Some(methods) = &self.methods {
            if methods
                .iter()
                .all(|candidate| !candidate.eq_ignore_ascii_case(method))
            {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DbQueryAccessMode {
    ReadOnly,
    ReadWrite,
}

impl DbQueryAccessMode {
    fn allows_write(&self) -> bool {
        matches!(self, DbQueryAccessMode::ReadWrite)
    }
}

impl Default for DbQueryAccessMode {
    fn default() -> Self {
        DbQueryAccessMode::ReadWrite
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct DbDestinationRule {
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub access: DbQueryAccessMode,
}

impl DbDestinationRule {
    fn host_port_matches(&self, host: &str, port: u16) -> bool {
        if !self.host.trim().eq_ignore_ascii_case(host.trim()) {
            return false;
        }
        match self.port {
            Some(expected_port) => expected_port == port,
            None => true,
        }
    }

    fn allows_query(&self, requires_write: bool) -> bool {
        if !requires_write {
            return true;
        }
        self.access.allows_write()
    }
}

impl<'de> Deserialize<'de> for OperationsScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        OperationsScopeInput::deserialize(deserializer)?
            .into_scope()
            .map_err(SerdeError::custom)
    }
}

pub struct ApiKey {
    value: SecretSlice<u8>,
    keys: KeysScope,
    operations: OperationsScope,
}

impl ApiKey {
    pub fn matches<T: AsRef<str>>(&self, other: T) -> bool {
        let key_bytes = self.value.expose_secret();
        let other_bytes = other.as_ref().as_bytes();
        key_bytes == other_bytes
    }

    pub fn keys_scope(&self) -> &KeysScope {
        &self.keys
    }

    pub fn operations_scope(&self) -> &OperationsScope {
        &self.operations
    }
}

impl Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKey")
            .field("value", &"********")
            .field("keys", &self.keys)
            .field("operations", &self.operations)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ApiKeyInput {
    /// Backwards compatibility: plain string → keys: "all", operations: "all"
    Legacy(String),
    Full {
        value: String,
        #[serde(default)]
        keys: KeysScope,
        #[serde(default)]
        operations: OperationsScope,
    },
}

impl<'de> Deserialize<'de> for ApiKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = ApiKeyInput::deserialize(deserializer)?;
        Ok(match input {
            ApiKeyInput::Legacy(s) => ApiKey {
                value: SecretSlice::from(s.as_bytes().to_vec()),
                keys: KeysScope::All,
                operations: OperationsScope::All,
            },
            ApiKeyInput::Full {
                value,
                keys,
                operations,
            } => ApiKey {
                value: SecretSlice::from(value.as_bytes().to_vec()),
                keys,
                operations,
            },
        })
    }
}

type KeySet = HashMap<String, VersionedKey>;

type VersionedKey = HashMap<u32, EncryptionKey>;

pub fn resolve_config_path(path: &Path) -> Result<PathBuf, anyhow::Error> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let cwd = std::env::current_dir()?;
        cwd.join(path)
    };
    let canonical = absolute.canonicalize()?;
    Ok(canonical)
}

pub async fn read_config(path: &Path, delete_after: bool) -> Result<Config, anyhow::Error> {
    let mut file = File::open(path).await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;
    let config: Config = serde_json::from_str(&contents)?;

    contents.zeroize();

    if delete_after {
        delete_config(path).await?;
    }

    Ok(config)
}

pub async fn delete_config(path: &Path) -> Result<(), anyhow::Error> {
    let mut file = File::open(path).await?;
    let length = file.metadata().await?.len();

    let mut rng = rand::rng();
    let mut buffer = vec![0u8; 4096];

    file.seek(SeekFrom::Start(0)).await?;

    let mut written = 0;
    while written < length {
        rng.fill_bytes(&mut buffer);
        let bytes_to_write = std::cmp::min(buffer.len(), (length - written) as usize);
        file.write_all(&buffer[..bytes_to_write]).await?;
        written += bytes_to_write as u64;
    }

    file.sync_all().await?;
    remove_file(path).await?;
    Ok(())
}

/// Read config from an environment variable containing either raw JSON or base64-encoded JSON.
/// The value must match the same JSON format as the file config. Raw JSON is tried first; if
/// deserialization fails, the value is decoded as standard base64 and parsed as UTF-8 JSON.
/// If `delete_after` is true, unsets the environment variable after reading.
pub fn read_config_from_env(
    env_var_name: &str,
    delete_after: bool,
) -> Result<Config, anyhow::Error> {
    let raw = std::env::var(env_var_name)
        .map_err(|_| anyhow::anyhow!("Environment variable '{}' is not set", env_var_name))?;

    let trimmed = raw.trim();

    let config = match serde_json::from_str::<Config>(trimmed) {
        Ok(c) => c,
        Err(json_err) => {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(trimmed)
                .map_err(|b64_err| {
                    anyhow::anyhow!(
                        "Config in env var '{}': not valid JSON ({}) and not valid base64 ({})",
                        env_var_name,
                        json_err,
                        b64_err
                    )
                })?;

            let json_str = Zeroizing::new(String::from_utf8(decoded).map_err(|e| {
                anyhow::anyhow!(
                    "Env var '{}' is not valid UTF-8 after base64 decode: {}",
                    env_var_name,
                    e
                )
            })?);

            serde_json::from_str(&json_str).map_err(|e| {
                anyhow::anyhow!("Invalid config JSON in env var '{}': {}", env_var_name, e)
            })?
        }
    };

    if delete_after {
        unset_env_var(env_var_name);
    }

    Ok(config)
}

/// Unset an environment variable. Used to clear secrets from the process environment.
pub fn unset_env_var(env_var_name: &str) {
    // SAFETY: We are the sole owner of the process environment during startup.
    unsafe { std::env::remove_var(env_var_name) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config(api_keys_json: &str) -> Config {
        let json = format!(
            r#"{{ "api_keys": {}, "server_port": 8080, "keys": {{}} }}"#,
            api_keys_json
        );
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn api_key_deserialize_from_string_backwards_compat() {
        let config = minimal_config(r#"["legacy-string-key"]"#);
        assert!(config.api_keys_required());
        assert!(config.validate_api_key("legacy-string-key"));
        assert!(!config.validate_api_key("wrong"));

        let key = &config.api_keys()[0];
        assert!(key.matches("legacy-string-key"));
        assert!(matches!(key.keys_scope(), KeysScope::All));
        assert!(key.operations_scope().allows_encrypt());
        assert!(key.operations_scope().allows_decrypt());
        assert!(key.operations_scope().allows_rotate());
        assert!(key.operations_scope().allows_verify());
        assert!(key.operations_scope().allows_sign());
        assert!(key.operations_scope().allows_proxy());
        assert!(key.operations_scope().allows_db_query());
    }

    #[test]
    fn api_key_deserialize_from_object_with_value_only() {
        let config = minimal_config(r#"[{ "value": "object-key" }]"#);
        assert!(config.validate_api_key("object-key"));
        let key = &config.api_keys()[0];
        assert!(key.matches("object-key"));
        assert!(matches!(key.keys_scope(), KeysScope::All));
        assert!(key.operations_scope().allows_encrypt());
        assert!(key.operations_scope().allows_decrypt());
        assert!(key.operations_scope().allows_rotate());
        assert!(key.operations_scope().allows_verify());
        assert!(key.operations_scope().allows_sign());
        assert!(key.operations_scope().allows_proxy());
        assert!(key.operations_scope().allows_db_query());
    }

    #[test]
    fn api_key_deserialize_from_object_with_explicit_all() {
        let config =
            minimal_config(r#"[{ "value": "full-key", "keys": "all", "operations": "all" }]"#);
        assert!(config.validate_api_key("full-key"));
        let key = &config.api_keys()[0];
        assert!(key.matches("full-key"));
        assert!(matches!(key.keys_scope(), KeysScope::All));
        assert!(key.operations_scope().allows_encrypt());
        assert!(key.operations_scope().allows_decrypt());
        assert!(key.operations_scope().allows_rotate());
        assert!(key.operations_scope().allows_verify());
        assert!(key.operations_scope().allows_sign());
        assert!(key.operations_scope().allows_proxy());
        assert!(key.operations_scope().allows_db_query());
    }

    #[test]
    fn api_key_deserialize_from_object_with_keys_list_and_operations_list() {
        let config = minimal_config(
            r#"[{ "value": "scoped-key", "keys": ["vault", "other"], "operations": ["encrypt", "decrypt"] }]"#,
        );
        assert!(config.validate_api_key("scoped-key"));
        let key = &config.api_keys()[0];
        assert!(key.matches("scoped-key"));

        let keys = key.keys_scope();
        assert!(keys.allows("vault"));
        assert!(keys.allows("other"));
        assert!(!keys.allows("unknown"));

        let ops = key.operations_scope();
        assert!(ops.allows_encrypt());
        assert!(ops.allows_decrypt());
        assert!(!ops.allows_rotate());
        assert!(!ops.allows_verify());
        assert!(!ops.allows_sign());
        assert!(!ops.allows_proxy());
        assert!(!ops.allows_db_query());
    }

    #[test]
    fn api_keys_mixed_string_and_object() {
        let config = minimal_config(
            r#"[ "string-key", { "value": "object-key", "operations": ["encrypt"] }]"#,
        );
        assert!(config.validate_api_key("string-key"));
        assert!(config.validate_api_key("object-key"));
        assert!(!config.validate_api_key("other"));

        let string_key = &config.api_keys()[0];
        assert!(matches!(string_key.keys_scope(), KeysScope::All));
        assert!(string_key.operations_scope().allows_rotate());
        assert!(string_key.operations_scope().allows_verify());
        assert!(string_key.operations_scope().allows_sign());
        assert!(string_key.operations_scope().allows_proxy());
        assert!(string_key.operations_scope().allows_db_query());

        let object_key = &config.api_keys()[1];
        assert!(object_key.operations_scope().allows_encrypt());
        assert!(!object_key.operations_scope().allows_decrypt());
        assert!(!object_key.operations_scope().allows_rotate());
        assert!(!object_key.operations_scope().allows_verify());
        assert!(!object_key.operations_scope().allows_sign());
        assert!(!object_key.operations_scope().allows_proxy());
        assert!(!object_key.operations_scope().allows_db_query());
    }

    #[test]
    fn keys_scope_deserialize_all() {
        let scope: KeysScope = serde_json::from_str(r#""all""#).unwrap();
        assert!(matches!(scope, KeysScope::All));
        assert!(scope.allows("any-key-name"));
    }

    #[test]
    fn keys_scope_deserialize_list() {
        let scope: KeysScope = serde_json::from_str(r#"["vault", "other"]"#).unwrap();
        match &scope {
            KeysScope::List(names) => {
                assert_eq!(names.len(), 2);
                assert!(names.contains(&"vault".to_string()));
                assert!(names.contains(&"other".to_string()));
            }
            KeysScope::All => panic!("expected List"),
        }
        assert!(scope.allows("vault"));
        assert!(scope.allows("other"));
        assert!(!scope.allows("unknown"));
    }

    #[test]
    fn keys_scope_reject_invalid_string() {
        let err = serde_json::from_str::<KeysScope>(r#""not-all""#).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("all") || msg.contains("keys"), "{}", msg);
    }

    #[test]
    fn operations_scope_deserialize_all() {
        let scope: OperationsScope = serde_json::from_str(r#""all""#).unwrap();
        assert!(matches!(scope, OperationsScope::All));
        assert!(scope.allows_encrypt());
        assert!(scope.allows_decrypt());
        assert!(scope.allows_rotate());
        assert!(scope.allows_verify());
        assert!(scope.allows_sign());
        assert!(scope.allows_proxy());
        assert!(scope.allows_db_query());
    }

    #[test]
    fn operations_scope_deserialize_list() {
        let scope: OperationsScope = serde_json::from_str(
            r#"["encrypt", "decrypt", "rotate", "verify", "sign", "proxy", "db_query"]"#,
        )
        .unwrap();
        match &scope {
            OperationsScope::List(ops) => assert_eq!(ops.len(), 7),
            OperationsScope::All => panic!("expected List"),
        }
        assert!(scope.allows_encrypt());
        assert!(scope.allows_decrypt());
        assert!(scope.allows_rotate());
        assert!(scope.allows_verify());
        assert!(scope.allows_sign());
        assert!(scope.allows_proxy());
        assert!(scope.allows_db_query());
    }

    #[test]
    fn operations_scope_deserialize_partial_list() {
        let scope: OperationsScope = serde_json::from_str(r#"["encrypt"]"#).unwrap();
        assert!(scope.allows_encrypt());
        assert!(!scope.allows_decrypt());
        assert!(!scope.allows_rotate());
        assert!(!scope.allows_verify());
        assert!(!scope.allows_sign());
        assert!(!scope.allows_proxy());
        assert!(!scope.allows_db_query());
    }

    #[test]
    fn operations_scope_reject_invalid_string() {
        let err = serde_json::from_str::<OperationsScope>(r#""read""#).unwrap_err();
        let msg = err.to_string();
        assert!(!msg.is_empty());
    }

    #[test]
    fn api_key_object_requires_value() {
        let json = r#"{"api_keys": [{"keys": "all", "operations": "all"}], "server_port": 8080, "keys": {}}"#;
        let result = serde_json::from_str::<Config>(json);
        assert!(
            result.is_err(),
            "object without value field must be rejected"
        );
    }

    #[test]
    fn destination_policy_allows_matching_host_and_method() {
        let json = r#"{
            "api_keys": ["k1"],
            "server_port": 8080,
            "keys": { "vault": { "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" } },
            "outbound_destinations": {
                "vault": [
                    { "host": "api.stripe.com", "methods": ["POST"], "path_prefix": "/v1/" }
                ]
            }
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert!(config.destination_allowed("vault", "POST", "api.stripe.com", "/v1/charges"));
        assert!(!config.destination_allowed("vault", "GET", "api.stripe.com", "/v1/charges"));
        assert!(!config.destination_allowed("vault", "POST", "api.stripe.com", "/v2/charges"));
    }

    #[test]
    fn destination_policy_defaults_to_allow_when_missing() {
        let json = r#"{
            "api_keys": ["k1"],
            "server_port": 8080,
            "keys": { "vault": { "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" } }
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert!(config.destination_allowed("vault", "GET", "example.com", "/"));
    }

    #[test]
    fn db_destination_policy_defaults_to_allow_when_missing() {
        let json = r#"{
            "api_keys": ["k1"],
            "server_port": 8080,
            "keys": { "vault": { "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" } }
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert!(config.db_destination_allowed("vault", "db.internal", 5432));
    }

    #[test]
    fn db_destination_policy_matches_host_and_optional_port() {
        let json = r#"{
            "api_keys": ["k1"],
            "server_port": 8080,
            "keys": { "vault": { "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" } },
            "db_destinations": {
                "vault": [
                    { "host": "db.internal", "port": 5432 },
                    { "host": "db-read.internal" }
                ]
            }
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert!(config.db_destination_allowed("vault", "db.internal", 5432));
        assert!(!config.db_destination_allowed("vault", "db.internal", 5433));
        assert!(config.db_destination_allowed("vault", "db-read.internal", 6000));
        assert!(!config.db_destination_allowed("vault", "unknown.internal", 5432));
    }

    #[test]
    fn db_destination_policy_enforces_read_only_vs_read_write_access() {
        let json = r#"{
            "api_keys": ["k1"],
            "server_port": 8080,
            "keys": { "vault": { "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" } },
            "db_destinations": {
                "vault": [
                    { "host": "db-read.internal", "access": "read_only" },
                    { "host": "db-write.internal", "access": "read_write" }
                ]
            }
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert!(config.db_destination_allows_query("vault", "db-read.internal", 5432, false));
        assert!(!config.db_destination_allows_query("vault", "db-read.internal", 5432, true));
        assert!(config.db_destination_allows_query("vault", "db-write.internal", 5432, false));
        assert!(config.db_destination_allows_query("vault", "db-write.internal", 5432, true));
    }

    #[test]
    fn db_destination_policy_empty_list_denies_all() {
        let json = r#"{
            "api_keys": ["k1"],
            "server_port": 8080,
            "keys": { "vault": { "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" } },
            "db_destinations": {
                "vault": []
            }
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert!(!config.db_destination_allowed("vault", "db.internal", 5432));
    }

    #[test]
    fn read_config_from_env_accepts_raw_json() {
        let json = r#"{
            "api_keys": [],
            "server_port": 9090,
            "keys": {}
        }"#;
        unsafe {
            std::env::set_var("TEST_SV_CONFIG_RAW", json);
        }
        let cfg = read_config_from_env("TEST_SV_CONFIG_RAW", false).unwrap();
        assert_eq!(cfg.server_port, 9090);
        unsafe {
            std::env::remove_var("TEST_SV_CONFIG_RAW");
        }
    }

    #[test]
    fn read_config_from_env_accepts_base64() {
        let json = r#"{"api_keys":[],"server_port":7070,"keys":{}}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        unsafe {
            std::env::set_var("TEST_SV_CONFIG_B64", b64);
        }
        let cfg = read_config_from_env("TEST_SV_CONFIG_B64", false).unwrap();
        assert_eq!(cfg.server_port, 7070);
        unsafe {
            std::env::remove_var("TEST_SV_CONFIG_B64");
        }
    }
}
