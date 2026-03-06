use std::{
    collections::HashMap,
    fmt::Debug,
    io::SeekFrom,
    path::{Path, PathBuf},
};

use base64::Engine;

use rand::Rng;
use secrets::{SecretBox, SecretVec};
use serde::{
    Deserialize,
    de::{Deserializer, Error as SerdeError},
};
use tokio::{
    fs::{File, remove_file},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};
use zeroize::{Zeroize, Zeroizing, ZeroizeOnDrop};

use crate::crypto::EncryptionKey;

#[derive(Debug, Deserialize)]
pub struct Config {
    api_keys: Vec<ApiKey>,
    pub server_port: u16,
    keys: KeySet,
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

    #[cfg(test)]
    pub fn api_keys(&self) -> &[ApiKey] {
        &self.api_keys
    }
}

// Config is used as axum state with a single-threaded runtime.
// The secret types inside are not thread-safe; current_thread ensures we never share across threads.
unsafe impl Send for Config {}
unsafe impl Sync for Config {}

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

/// Allowed operation: encrypt, decrypt, or rotate.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyOperation {
    Encrypt,
    Decrypt,
    Rotate,
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
                    Err("operations must be the string \"all\" or an array of \"encrypt\", \"decrypt\", \"rotate\"".to_string())
                }
            }
            OperationsScopeInput::List(l) => Ok(OperationsScope::List(l)),
        }
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
    value: SecretVec<u8>,
    keys: KeysScope,
    operations: OperationsScope,
}

impl ApiKey {
    pub fn matches<T: AsRef<str>>(&self, other: T) -> bool {
        let key_bytes = self.value.borrow();
        let other_bytes = other.as_ref().as_bytes();
        &*key_bytes == other_bytes
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
                value: SecretVec::new(s.len(), |buf| buf.copy_from_slice(s.as_bytes())),
                keys: KeysScope::All,
                operations: OperationsScope::All,
            },
            ApiKeyInput::Full {
                value,
                keys,
                operations,
            } => ApiKey {
                value: SecretVec::new(value.len(), |buf| buf.copy_from_slice(value.as_bytes())),
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

/// Read config from an environment variable containing base64-encoded JSON.
/// The env var value must be the same JSON format as the file config.
/// If `delete_after` is true, unsets the environment variable after reading.
pub fn read_config_from_env(env_var_name: &str, delete_after: bool) -> Result<Config, anyhow::Error> {
    let encoded = std::env::var(env_var_name)
        .map_err(|_| anyhow::anyhow!("Environment variable '{}' is not set", env_var_name))?;

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .map_err(|e| anyhow::anyhow!("Invalid base64 in env var '{}': {}", env_var_name, e))?;

    let json_str = Zeroizing::new(
        String::from_utf8(decoded)
            .map_err(|e| anyhow::anyhow!("Env var '{}' is not valid UTF-8: {}", env_var_name, e))?,
    );

    let config: Config = serde_json::from_str(&*json_str)
        .map_err(|e| anyhow::anyhow!("Invalid config JSON in env var '{}': {}", env_var_name, e))?;

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
        assert_eq!(config.api_keys_required(), true);
        assert!(config.validate_api_key("legacy-string-key"));
        assert!(!config.validate_api_key("wrong"));

        let key = &config.api_keys()[0];
        assert!(key.matches("legacy-string-key"));
        assert!(matches!(key.keys_scope(), KeysScope::All));
        assert!(key.operations_scope().allows_encrypt());
        assert!(key.operations_scope().allows_decrypt());
        assert!(key.operations_scope().allows_rotate());
    }

    #[test]
    fn api_key_deserialize_from_object_with_value_only() {
        let config = minimal_config(
            r#"[{ "value": "object-key" }]"#,
        );
        assert!(config.validate_api_key("object-key"));
        let key = &config.api_keys()[0];
        assert!(key.matches("object-key"));
        assert!(matches!(key.keys_scope(), KeysScope::All));
        assert!(key.operations_scope().allows_encrypt());
        assert!(key.operations_scope().allows_decrypt());
        assert!(key.operations_scope().allows_rotate());
    }

    #[test]
    fn api_key_deserialize_from_object_with_explicit_all() {
        let config = minimal_config(
            r#"[{ "value": "full-key", "keys": "all", "operations": "all" }]"#,
        );
        assert!(config.validate_api_key("full-key"));
        let key = &config.api_keys()[0];
        assert!(key.matches("full-key"));
        assert!(matches!(key.keys_scope(), KeysScope::All));
        assert!(key.operations_scope().allows_encrypt());
        assert!(key.operations_scope().allows_decrypt());
        assert!(key.operations_scope().allows_rotate());
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

        let object_key = &config.api_keys()[1];
        assert!(object_key.operations_scope().allows_encrypt());
        assert!(!object_key.operations_scope().allows_decrypt());
        assert!(!object_key.operations_scope().allows_rotate());
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
    }

    #[test]
    fn operations_scope_deserialize_list() {
        let scope: OperationsScope =
            serde_json::from_str(r#"["encrypt", "decrypt", "rotate"]"#).unwrap();
        match &scope {
            OperationsScope::List(ops) => assert_eq!(ops.len(), 3),
            OperationsScope::All => panic!("expected List"),
        }
        assert!(scope.allows_encrypt());
        assert!(scope.allows_decrypt());
        assert!(scope.allows_rotate());
    }

    #[test]
    fn operations_scope_deserialize_partial_list() {
        let scope: OperationsScope = serde_json::from_str(r#"["encrypt"]"#).unwrap();
        assert!(scope.allows_encrypt());
        assert!(!scope.allows_decrypt());
        assert!(!scope.allows_rotate());
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
        assert!(result.is_err(), "object without value field must be rejected");
    }
}
