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
    de::{Deserializer, Error as SerdeError, Visitor},
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
}

// Config is used as axum state with a single-threaded runtime.
// The secret types inside are not thread-safe; current_thread ensures we never share across threads.
unsafe impl Send for Config {}
unsafe impl Sync for Config {}

pub struct ApiKey {
    key: SecretVec<u8>,
}

impl ApiKey {
    pub fn matches<T: AsRef<str>>(&self, other: T) -> bool {
        let key_bytes = self.key.borrow();
        let other_bytes = other.as_ref().as_bytes();
        &*key_bytes == other_bytes
    }
}

impl Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKey").field("key", &"********").finish()
    }
}

impl<'de> serde::Deserialize<'de> for ApiKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ApiKeyVisitor;

        impl<'de> Visitor<'de> for ApiKeyVisitor {
            type Value = ApiKey;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "a string API key")
            }

            fn visit_str<E>(self, v: &str) -> Result<ApiKey, E>
            where
                E: SerdeError,
            {
                let key_bytes: Vec<u8> = v.as_bytes().to_vec();
                let len = key_bytes.len();
                Ok(ApiKey {
                    key: SecretVec::new(len, |buf| buf.copy_from_slice(&key_bytes)),
                })
            }
        }

        deserializer.deserialize_str(ApiKeyVisitor)
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
