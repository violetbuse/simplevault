use std::fmt::{Display, Formatter};
use std::sync::Arc;

use async_trait::async_trait;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(any(test, feature = "test-utils"))]
use serde_json::json;

#[cfg(any(test, feature = "test-utils"))]
use crate::config::Config;
use crate::crypto::CipherText;
use crate::db_query::{DbQueryResult, TypedQueryParam};
use crate::proxy_substitute::{OutboundRequest, ProxySubstituteResponse};

#[derive(Clone)]
pub struct SimpleVaultClient {
    transport: Arc<dyn SimpleVaultTransport>,
}

impl std::fmt::Debug for SimpleVaultClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimpleVaultClient")
            .field("key_name", &self.transport.key_name())
            .finish()
    }
}

impl SimpleVaultClient {
    pub fn new<T>(transport: T) -> Self
    where
        T: SimpleVaultTransport,
    {
        Self {
            transport: Arc::new(transport),
        }
    }

    pub fn key_name(&self) -> &str {
        &self.transport.key_name()
    }

    pub async fn encrypt(
        &self,
        plaintext: impl Into<String>,
    ) -> Result<CipherTextObject, ClientError> {
        self.post_json(
            "encrypt",
            EncryptRequest {
                plaintext: plaintext.into(),
            },
        )
        .await
    }

    pub async fn decrypt(&self, ciphertext: CipherText) -> Result<PlainTextObject, ClientError> {
        self.post_json("decrypt", CipherTextObject { ciphertext })
            .await
    }

    pub async fn rotate(&self, ciphertext: CipherText) -> Result<CipherTextObject, ClientError> {
        self.post_json("rotate", CipherTextObject { ciphertext })
            .await
    }

    pub async fn create_signature(
        &self,
        request: CreateSignatureRequest,
    ) -> Result<CreateSignatureResponse, ClientError> {
        self.post_json("create-signature", request).await
    }

    pub async fn verify_signature(
        &self,
        request: VerifySignatureRequest,
    ) -> Result<VerifySignatureResponse, ClientError> {
        self.post_json("verify-signature", request).await
    }

    pub async fn proxy_substitute(
        &self,
        request: ProxySubstituteRequest,
    ) -> Result<ProxySubstituteResponse, ClientError> {
        self.post_json("proxy-substitute", request).await
    }

    pub async fn db_query(&self, request: DbQueryRequest) -> Result<DbQueryResult, ClientError> {
        self.post_json("db-query", request).await
    }

    pub async fn version(&self) -> Result<VersionResponse, ClientError> {
        self.get_json("version").await
    }

    async fn post_json<B, R>(&self, endpoint: &str, body: B) -> Result<R, ClientError>
    where
        B: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let body = serde_json::to_value(body).map_err(ClientError::Serialize)?;
        let value = self
            .transport
            .send_json(
                HttpMethod::Post,
                self.transport.key_name(),
                endpoint,
                Some(body),
            )
            .await?;
        serde_json::from_value(value).map_err(ClientError::Deserialize)
    }

    async fn get_json<R>(&self, endpoint: &str) -> Result<R, ClientError>
    where
        R: for<'de> Deserialize<'de>,
    {
        let value = self
            .transport
            .send_json(HttpMethod::Get, self.transport.key_name(), endpoint, None)
            .await?;
        serde_json::from_value(value).map_err(ClientError::Deserialize)
    }
}

#[derive(Debug, Clone)]
pub struct HttpConfig {
    key_name: String,
    base_url: String,
    api_key: Option<String>,
}

impl SimpleVaultClient {
    pub fn with_http_transport(config: HttpConfig) -> Self {
        Self::new(HttpTransport::new(
            config.base_url,
            config.key_name,
            config.api_key,
        ))
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl SimpleVaultClient {
    pub fn with_test_transport(
        config: Option<Value>,
        key_name: impl Into<String>,
        api_key: Option<String>,
    ) -> Result<Self, ClientError> {
        let config_value = config.unwrap_or_else(default_permissive_test_config);
        let parsed_config: Config =
            serde_json::from_value(config_value).map_err(ClientError::InvalidConfig)?;
        let app = crate::api::build_router(parsed_config);
        let transport = InMemoryTransport::new(app, key_name.into(), api_key);
        Ok(Self::new(transport))
    }
}

#[async_trait]
pub trait SimpleVaultTransport: Send + Sync + 'static {
    async fn send_json(
        &self,
        method: HttpMethod,
        key_name: &str,
        endpoint: &str,
        body: Option<Value>,
    ) -> Result<Value, ClientError>;

    fn key_name(&self) -> &str;
}

#[derive(Debug, Clone, Copy)]
pub enum HttpMethod {
    Get,
    Post,
}

#[derive(Debug)]
pub enum ClientError {
    Transport(String),
    Serialize(serde_json::Error),
    Deserialize(serde_json::Error),
    InvalidConfig(serde_json::Error),
    HttpStatus {
        status: u16,
        message: String,
        body: Option<Value>,
    },
}

impl Display for ClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Transport(message) => write!(f, "transport error: {}", message),
            ClientError::Serialize(error) => write!(f, "request serialization error: {}", error),
            ClientError::Deserialize(error) => {
                write!(f, "response deserialization error: {}", error)
            }
            ClientError::InvalidConfig(error) => write!(f, "invalid test config: {}", error),
            ClientError::HttpStatus {
                status, message, ..
            } => write!(f, "SimpleVault {}: {}", status, message),
        }
    }
}

impl std::error::Error for ClientError {}

#[derive(Debug, Clone)]
pub struct HttpTransport {
    base_url: String,
    key_name: String,
    api_key: Option<String>,
    client: reqwest::Client,
}

impl HttpTransport {
    pub fn new(
        base_url: impl Into<String>,
        key_name: impl Into<String>,
        api_key: Option<String>,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            key_name: key_name.into(),
            api_key,
            client: reqwest::Client::new(),
        }
    }

    fn url_for(&self, key_name: &str, endpoint: &str) -> String {
        let encoded_key_name: String =
            form_urlencoded::byte_serialize(key_name.as_bytes()).collect();
        format!("{}/v1/{}/{}", self.base_url, encoded_key_name, endpoint)
    }
}

#[async_trait]
impl SimpleVaultTransport for HttpTransport {
    async fn send_json(
        &self,
        method: HttpMethod,
        key_name: &str,
        endpoint: &str,
        body: Option<Value>,
    ) -> Result<Value, ClientError> {
        let url = self.url_for(key_name, endpoint);
        let mut request = match method {
            HttpMethod::Get => self.client.get(url),
            HttpMethod::Post => self.client.post(url),
        };

        if let Some(api_key) = &self.api_key {
            request = request
                .header("Authorization", format!("Bearer {}", api_key))
                .header("x-api-key", api_key);
        }

        if let Some(payload) = body {
            request = request.json(&payload);
        }

        let response = request
            .send()
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        let status = response.status();
        let body_text = response
            .text()
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?;

        let parsed = parse_json_text(&body_text)?;
        if !status.is_success() {
            return Err(status_error(status.as_u16(), parsed));
        }
        Ok(parsed.unwrap_or(Value::Null))
    }

    fn key_name(&self) -> &str {
        &self.key_name
    }
}

#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Clone)]
pub struct InMemoryTransport {
    app: axum::Router,
    key_name: String,
    api_key: Option<String>,
}

#[cfg(any(test, feature = "test-utils"))]
impl InMemoryTransport {
    pub fn new(app: axum::Router, key_name: impl Into<String>, api_key: Option<String>) -> Self {
        Self {
            app,
            key_name: key_name.into(),
            api_key,
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
#[async_trait]
impl SimpleVaultTransport for InMemoryTransport {
    async fn send_json(
        &self,
        method: HttpMethod,
        key_name: &str,
        endpoint: &str,
        body: Option<Value>,
    ) -> Result<Value, ClientError> {
        use axum::body::Body;
        use axum::http::Request;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let method_value = match method {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
        };
        let path = format!("/v1/{}/{}", key_name, endpoint);
        let mut builder = Request::builder().method(method_value).uri(path);

        if let Some(api_key) = &self.api_key {
            builder = builder
                .header("Authorization", format!("Bearer {}", api_key))
                .header("x-api-key", api_key);
        }

        let request = match body {
            Some(payload) => {
                let body_string =
                    serde_json::to_string(&payload).map_err(ClientError::Serialize)?;
                builder
                    .header("content-type", "application/json")
                    .body(Body::from(body_string))
                    .map_err(|error| ClientError::Transport(error.to_string()))?
            }
            None => builder
                .body(Body::empty())
                .map_err(|error| ClientError::Transport(error.to_string()))?,
        };

        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        let status = response.status();
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?
            .to_bytes();
        let body_text = String::from_utf8(body_bytes.to_vec())
            .map_err(|error| ClientError::Transport(error.to_string()))?;

        let parsed = parse_json_text(&body_text)?;
        if !status.is_success() {
            return Err(status_error(status.as_u16(), parsed));
        }
        Ok(parsed.unwrap_or(Value::Null))
    }

    fn key_name(&self) -> &str {
        &self.key_name
    }
}

fn parse_json_text(text: &str) -> Result<Option<Value>, ClientError> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    serde_json::from_str::<Value>(text)
        .map(Some)
        .map_err(ClientError::Deserialize)
}

fn status_error(status: u16, body: Option<Value>) -> ClientError {
    let message = body
        .as_ref()
        .and_then(|value| value.get("error"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .unwrap_or_else(|| {
            StatusCode::from_u16(status)
                .map(|code| code.to_string())
                .unwrap_or_else(|_| "unknown status".to_string())
        });
    ClientError::HttpStatus {
        status,
        message,
        body,
    }
}

#[cfg(any(test, feature = "test-utils"))]
fn default_permissive_test_config() -> Value {
    json!({
        "api_keys": [],
        "server_port": 8080,
        "keys": {
            "vault": {
                "1": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            }
        }
    })
}

#[derive(Debug, Serialize)]
struct EncryptRequest {
    plaintext: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CipherTextObject {
    pub ciphertext: CipherText,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlainTextObject {
    pub plaintext: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifySignatureRequest {
    pub ciphertext: CipherText,
    pub payload: String,
    pub signature: String,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifySignatureResponse {
    pub verified: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSignatureRequest {
    pub ciphertext: CipherText,
    pub payload: String,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSignatureResponse {
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxySubstituteRequest {
    pub ciphertext: CipherText,
    pub request: OutboundRequest,
    #[serde(default)]
    pub placeholder: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DbQueryRequest {
    pub ciphertext: CipherText,
    pub query: DbQueryPayload,
    #[serde(default)]
    pub options: Option<DbQueryOptions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbQueryPayload {
    pub sql: String,
    #[serde(default)]
    pub params: Option<Vec<TypedQueryParam>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbQueryOptions {
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub max_rows: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionResponse {
    pub version: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::{DateTime, FixedOffset, NaiveDateTime};
    use postgresql_embedded::PostgreSQL;
    use serde_json::json;

    use crate::api;
    use crate::config::Config;
    use crate::test_pg::TestPg;

    fn config_no_auth() -> Config {
        serde_json::from_value(json!({
            "api_keys": [],
            "server_port": 8080,
            "keys": {
                "vault": {
                    "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                }
            }
        }))
        .expect("config should deserialize")
    }

    fn config_with_auth(api_key: &str) -> Config {
        serde_json::from_value(json!({
            "api_keys": [api_key],
            "server_port": 8080,
            "keys": {
                "vault": {
                    "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                }
            }
        }))
        .expect("config should deserialize")
    }

    fn config_with_key_versions() -> Config {
        serde_json::from_value(json!({
            "api_keys": [],
            "server_port": 8080,
            "keys": {
                "vault": {
                    "1": "0000000000000000000000000000000000000000000000000000000000000000",
                    "2": "1111111111111111111111111111111111111111111111111111111111111111"
                }
            }
        }))
        .expect("config should deserialize")
    }

    fn config_with_only_v1_key() -> Config {
        serde_json::from_value(json!({
            "api_keys": [],
            "server_port": 8080,
            "keys": {
                "vault": {
                    "1": "0000000000000000000000000000000000000000000000000000000000000000"
                }
            }
        }))
        .expect("config should deserialize")
    }

    fn config_without_vault_key() -> Config {
        serde_json::from_value(json!({
            "api_keys": [],
            "server_port": 8080,
            "keys": {
                "other": {
                    "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                }
            }
        }))
        .expect("config should deserialize")
    }

    fn config_with_operations_encrypt_decrypt_only() -> Config {
        serde_json::from_value(json!({
            "api_keys": [{
                "value": "encrypt-decrypt-key",
                "keys": "all",
                "operations": ["encrypt", "decrypt"]
            }],
            "server_port": 8080,
            "keys": {
                "vault": {
                    "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                }
            }
        }))
        .expect("config should deserialize")
    }

    fn config_with_operations_verify_only() -> Config {
        serde_json::from_value(json!({
            "api_keys": [{
                "value": "verify-only-key",
                "keys": "all",
                "operations": ["verify"]
            }],
            "server_port": 8080,
            "keys": {
                "vault": {
                    "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                }
            }
        }))
        .expect("config should deserialize")
    }

    fn config_with_operations_sign_only() -> Config {
        serde_json::from_value(json!({
            "api_keys": [{
                "value": "sign-only-key",
                "keys": "all",
                "operations": ["sign"]
            }],
            "server_port": 8080,
            "keys": {
                "vault": {
                    "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                }
            }
        }))
        .expect("config should deserialize")
    }

    fn config_with_operations_db_query_only() -> Config {
        serde_json::from_value(json!({
            "api_keys": [{
                "value": "db-query-only-key",
                "keys": "all",
                "operations": ["db_query"]
            }],
            "server_port": 8080,
            "keys": {
                "vault": {
                    "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                }
            }
        }))
        .expect("config should deserialize")
    }

    fn config_with_operations_encrypt_only() -> Config {
        serde_json::from_value(json!({
            "api_keys": [{
                "value": "encrypt-only-key",
                "keys": "all",
                "operations": ["encrypt"]
            }],
            "server_port": 8080,
            "keys": {
                "vault": {
                    "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                }
            }
        }))
        .expect("config should deserialize")
    }

    fn db_query_config_for_connection_string(connection_string: &str, access: &str) -> Config {
        let targets = crate::db_query::parse_connection_targets(connection_string)
            .expect("connection string should parse");
        let (allowed_host, allowed_port) = targets.first().cloned().expect("host should exist");
        serde_json::from_value(json!({
            "api_keys": [{
                "value": "db-query-key",
                "keys": "all",
                "operations": ["encrypt", "db_query"]
            }],
            "server_port": 8080,
            "keys": {
                "vault": {
                    "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                }
            },
            "db_destinations": {
                "vault": [{
                    "host": allowed_host,
                    "port": allowed_port,
                    "access": access
                }]
            }
        }))
        .expect("config should deserialize")
    }

    fn make_client(config: Config, api_key: Option<&str>) -> SimpleVaultClient {
        let app = api::build_router(config);
        let transport = InMemoryTransport::new(app, "vault", api_key.map(str::to_string));
        SimpleVaultClient::new(transport)
    }

    fn clone_ciphertext(ciphertext: &CipherText) -> CipherText {
        serde_json::from_value(serde_json::to_value(ciphertext).expect("serialize ciphertext"))
            .expect("deserialize ciphertext")
    }

    fn assert_http_status(error: ClientError, expected_status: u16) -> Option<Value> {
        match error {
            ClientError::HttpStatus { status, body, .. } => {
                assert_eq!(status, expected_status);
                body
            }
            other => panic!("expected http status error, got {other:?}"),
        }
    }

    async fn make_db_fixture(
        migration_sql: &str,
        access: &str,
    ) -> (PostgreSQL, SimpleVaultClient, CipherText) {
        let test_pg = TestPg::new();
        let (instance, connection_string) = test_pg
            .create(migration_sql)
            .await
            .expect("embedded postgres should start");
        let client = make_client(
            db_query_config_for_connection_string(&connection_string, access),
            Some("db-query-key"),
        );
        let ciphertext = client
            .encrypt(connection_string)
            .await
            .expect("encrypt db connection string")
            .ciphertext;
        (instance, client, ciphertext)
    }

    fn unique_table_name(prefix: &str) -> String {
        format!(
            "{}_{}_{}",
            prefix,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("unix epoch")
                .as_nanos(),
            rand::random::<u32>()
        )
    }

    #[tokio::test]
    async fn client_reports_key_name_and_debug_without_transport_details() {
        let client = make_client(config_no_auth(), None);
        assert_eq!(client.key_name(), "vault");
        assert_eq!(
            format!("{client:?}"),
            "SimpleVaultClient { key_name: \"vault\" }"
        );
    }

    #[tokio::test]
    async fn with_test_transport_uses_default_config() {
        let client = SimpleVaultClient::with_test_transport(None, "vault", None)
            .expect("default test transport");
        let encrypted = client
            .encrypt("hello")
            .await
            .expect("encrypt should succeed");
        let decrypted = client
            .decrypt(clone_ciphertext(&encrypted.ciphertext))
            .await
            .expect("decrypt should succeed");
        assert_eq!(decrypted.plaintext, "hello");
    }

    #[tokio::test]
    async fn with_test_transport_rejects_invalid_config() {
        let error =
            SimpleVaultClient::with_test_transport(Some(json!({ "server_port": "bad" })), "", None)
                .expect_err("invalid config should fail");
        assert!(matches!(error, ClientError::InvalidConfig(_)));
    }

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip() {
        let client = make_client(config_no_auth(), None);
        let encrypted = client.encrypt("integration secret").await.expect("encrypt");
        let decrypted = client
            .decrypt(clone_ciphertext(&encrypted.ciphertext))
            .await
            .expect("decrypt");
        assert_eq!(decrypted.plaintext, "integration secret");
    }

    #[tokio::test]
    async fn version_returns_latest_key_version() {
        let client = make_client(config_with_key_versions(), None);
        let version = client.version().await.expect("version should succeed");
        assert_eq!(version.version, 2);
    }

    #[tokio::test]
    async fn rotate_reencrypts_with_latest_key_version() {
        let client = make_client(config_with_key_versions(), None);
        let old_ciphertext = make_client(config_with_only_v1_key(), None)
            .encrypt("rotate me")
            .await
            .expect("encrypt")
            .ciphertext;
        let rotated = client.rotate(old_ciphertext).await.expect("rotate");
        assert_eq!(rotated.ciphertext.key_version, 2);

        let decrypted = client
            .decrypt(rotated.ciphertext)
            .await
            .expect("decrypt rotated");
        assert_eq!(decrypted.plaintext, "rotate me");
    }

    #[tokio::test]
    async fn decrypt_reports_key_not_found() {
        let client = make_client(config_without_vault_key(), None);
        let ciphertext = make_client(config_no_auth(), None)
            .encrypt("secret")
            .await
            .expect("encrypt")
            .ciphertext;
        let error = client
            .decrypt(ciphertext)
            .await
            .expect_err("decrypt should fail");
        let body = assert_http_status(error, 500).expect("error body");
        assert_eq!(
            body["error"].as_str(),
            Some("key not found: vault (version 1)")
        );
    }

    #[tokio::test]
    async fn create_and_verify_signature_roundtrip() {
        let client = make_client(config_no_auth(), None);
        let secret = client
            .encrypt("whsec_client_secret")
            .await
            .expect("encrypt secret");
        let payload_hex = hex::encode(br#"{"id":"evt_client"}"#);

        let created = client
            .create_signature(CreateSignatureRequest {
                ciphertext: clone_ciphertext(&secret.ciphertext),
                payload: payload_hex.clone(),
                algorithm: "hmac-sha256".to_string(),
            })
            .await
            .expect("create signature");

        let verified = client
            .verify_signature(VerifySignatureRequest {
                ciphertext: clone_ciphertext(&secret.ciphertext),
                payload: payload_hex,
                signature: created.signature,
                algorithm: "hmac-sha256".to_string(),
            })
            .await
            .expect("verify signature");

        assert!(verified.verified);
    }

    #[tokio::test]
    async fn verify_signature_returns_false_for_mismatch() {
        let client = make_client(config_no_auth(), None);
        let secret = client
            .encrypt("whsec_client_secret")
            .await
            .expect("encrypt secret");

        let verified = client
            .verify_signature(VerifySignatureRequest {
                ciphertext: secret.ciphertext,
                payload: hex::encode("payload"),
                signature: hex::encode("wrong"),
                algorithm: "hmac-sha256".to_string(),
            })
            .await
            .expect("verify signature");

        assert!(!verified.verified);
    }

    #[tokio::test]
    async fn create_signature_rejects_unknown_algorithm() {
        let client = make_client(config_no_auth(), None);
        let secret = client.encrypt("whsec").await.expect("encrypt secret");
        let error = client
            .create_signature(CreateSignatureRequest {
                ciphertext: secret.ciphertext,
                payload: hex::encode("payload"),
                algorithm: "unknown".to_string(),
            })
            .await
            .expect_err("unknown algorithm should fail");
        let body = assert_http_status(error, 500).expect("error body");
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("unsupported signature algorithm")
        );
    }

    #[tokio::test]
    async fn auth_required_rejects_missing_key() {
        let client = make_client(config_with_auth("secret-key"), None);
        let error = client
            .encrypt("hello")
            .await
            .expect_err("missing key should fail");
        let body = assert_http_status(error, 401).expect("error body");
        assert_eq!(body["error"].as_str(), Some("missing or invalid API key"));
    }

    #[tokio::test]
    async fn auth_required_rejects_invalid_key() {
        let client = make_client(config_with_auth("secret-key"), Some("wrong-key"));
        let error = client
            .encrypt("hello")
            .await
            .expect_err("invalid key should fail");
        let body = assert_http_status(error, 401).expect("error body");
        assert_eq!(body["error"].as_str(), Some("missing or invalid API key"));
    }

    #[tokio::test]
    async fn rotate_requires_rotate_scope() {
        let restricted_client = make_client(
            config_with_operations_encrypt_decrypt_only(),
            Some("encrypt-decrypt-key"),
        );
        let unrestricted_client = make_client(config_no_auth(), None);
        let ciphertext = unrestricted_client
            .encrypt("secret")
            .await
            .expect("encrypt")
            .ciphertext;

        let error = restricted_client
            .rotate(ciphertext)
            .await
            .expect_err("rotate should be forbidden");
        assert_http_status(error, 403);
    }

    #[tokio::test]
    async fn verify_requires_verify_scope() {
        let client = make_client(config_with_operations_sign_only(), Some("sign-only-key"));
        let ciphertext = make_client(config_no_auth(), None)
            .encrypt("secret")
            .await
            .expect("encrypt")
            .ciphertext;
        let error = client
            .verify_signature(VerifySignatureRequest {
                ciphertext,
                payload: hex::encode("payload"),
                signature: hex::encode("sig"),
                algorithm: "hmac-sha256".to_string(),
            })
            .await
            .expect_err("verify should be forbidden");
        assert_http_status(error, 403);
    }

    #[tokio::test]
    async fn sign_requires_sign_scope() {
        let client = make_client(
            config_with_operations_verify_only(),
            Some("verify-only-key"),
        );
        let ciphertext = make_client(config_no_auth(), None)
            .encrypt("secret")
            .await
            .expect("encrypt")
            .ciphertext;
        let error = client
            .create_signature(CreateSignatureRequest {
                ciphertext,
                payload: hex::encode("payload"),
                algorithm: "hmac-sha256".to_string(),
            })
            .await
            .expect_err("sign should be forbidden");
        assert_http_status(error, 403);
    }

    #[tokio::test]
    async fn proxy_substitute_requires_proxy_scope() {
        let client = make_client(
            config_with_operations_encrypt_only(),
            Some("encrypt-only-key"),
        );
        let ciphertext = client.encrypt("secret").await.expect("encrypt").ciphertext;
        let error = client
            .proxy_substitute(ProxySubstituteRequest {
                ciphertext,
                request: OutboundRequest {
                    method: "GET".to_string(),
                    url: "https://example.com".to_string(),
                    headers: None,
                    body: None,
                },
                placeholder: None,
            })
            .await
            .expect_err("proxy should be forbidden");
        assert_http_status(error, 403);
    }

    #[tokio::test]
    async fn db_query_requires_db_query_scope() {
        let client = make_client(
            config_with_operations_encrypt_only(),
            Some("encrypt-only-key"),
        );
        let ciphertext = client
            .encrypt("postgres://user:pass@db.internal:5432/app")
            .await
            .expect("encrypt")
            .ciphertext;
        let error = client
            .db_query(DbQueryRequest {
                ciphertext,
                query: DbQueryPayload {
                    sql: "select 1".to_string(),
                    params: None,
                },
                options: None,
            })
            .await
            .expect_err("db query should be forbidden");
        assert_http_status(error, 403);
    }

    #[tokio::test]
    async fn db_query_rejects_disallowed_destination() {
        let client = make_client(
            serde_json::from_value(json!({
                "api_keys": [{
                    "value": "db-query-key",
                    "keys": "all",
                    "operations": ["encrypt", "db_query"]
                }],
                "server_port": 8080,
                "keys": {
                    "vault": {
                        "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    }
                },
                "db_destinations": {
                    "vault": [{
                        "host": "db-allowed.internal",
                        "port": 5432
                    }]
                }
            }))
            .expect("config should deserialize"),
            Some("db-query-key"),
        );

        let ciphertext = client
            .encrypt("postgres://user:pass@db-blocked.internal:5432/app")
            .await
            .expect("encrypt")
            .ciphertext;
        let error = client
            .db_query(DbQueryRequest {
                ciphertext,
                query: DbQueryPayload {
                    sql: "select 1".to_string(),
                    params: None,
                },
                options: None,
            })
            .await
            .expect_err("destination should be forbidden");
        assert_http_status(error, 403);
    }

    #[tokio::test]
    async fn db_query_allows_when_destination_policy_missing() {
        let client = make_client(
            config_with_operations_db_query_only(),
            Some("db-query-only-key"),
        );
        let ciphertext = make_client(config_no_auth(), None)
            .encrypt("postgres://user:pass@db.internal:5432/app")
            .await
            .expect("encrypt")
            .ciphertext;
        let error = client
            .db_query(DbQueryRequest {
                ciphertext,
                query: DbQueryPayload {
                    sql: "select 1".to_string(),
                    params: None,
                },
                options: Some(DbQueryOptions {
                    timeout_ms: Some(200),
                    max_rows: None,
                }),
            })
            .await
            .expect_err("query should reach database layer");
        match error {
            ClientError::HttpStatus { status, .. } => assert_ne!(status, 403),
            other => panic!("expected http status error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn db_query_read_only_destination_allows_read_queries() {
        let (instance, client, ciphertext) = make_db_fixture("", "read_only").await;

        let result = client
            .db_query(DbQueryRequest {
                ciphertext,
                query: DbQueryPayload {
                    sql: "select 1 as n".to_string(),
                    params: None,
                },
                options: Some(DbQueryOptions {
                    timeout_ms: Some(3000),
                    max_rows: Some(100),
                }),
            })
            .await
            .expect("read query should succeed");

        assert_eq!(result.row_count, 1);
        assert_eq!(result.rows[0][0].as_i64(), Some(1));

        instance
            .stop()
            .await
            .expect("embedded postgres should stop");
    }

    #[tokio::test]
    async fn db_query_read_only_destination_rejects_write_queries() {
        let (instance, client, ciphertext) = make_db_fixture("", "read_only").await;

        let error = client
            .db_query(DbQueryRequest {
                ciphertext,
                query: DbQueryPayload {
                    sql: "create table blocked_write_test (id int)".to_string(),
                    params: None,
                },
                options: None,
            })
            .await
            .expect_err("write query should be forbidden");
        assert_http_status(error, 403);

        instance
            .stop()
            .await
            .expect("embedded postgres should stop");
    }

    #[tokio::test]
    async fn db_query_read_only_destination_rejects_writable_cte_queries() {
        let (instance, client, ciphertext) = make_db_fixture("", "read_only").await;

        let error = client
            .db_query(DbQueryRequest {
                ciphertext,
                query: DbQueryPayload {
                    sql: "with deleted as (delete from t where false returning *) select * from deleted"
                        .to_string(),
                    params: None,
                },
                options: None,
            })
            .await
            .expect_err("writable cte should be forbidden");
        assert_http_status(error, 403);

        instance
            .stop()
            .await
            .expect("embedded postgres should stop");
    }

    #[tokio::test]
    async fn db_query_executes_against_real_postgres() {
        let (instance, client, ciphertext) = make_db_fixture("", "read_write").await;

        let result = client
            .db_query(DbQueryRequest {
                ciphertext,
                query: DbQueryPayload {
                    sql: "select $1::int as n, $2::text as t".to_string(),
                    params: Some(vec![
                        TypedQueryParam::Int32(7),
                        TypedQueryParam::Text("ok".to_string()),
                    ]),
                },
                options: Some(DbQueryOptions {
                    timeout_ms: Some(3000),
                    max_rows: Some(100),
                }),
            })
            .await
            .expect("db query should succeed");

        assert_eq!(result.row_count, 1);
        assert_eq!(result.rows[0][0].as_i64(), Some(7));
        assert_eq!(result.rows[0][1].as_str(), Some("ok"));

        instance
            .stop()
            .await
            .expect("embedded postgres should stop");
    }

    #[tokio::test]
    async fn db_query_reports_descriptive_sql_errors() {
        let (instance, client, ciphertext) = make_db_fixture("", "read_write").await;

        let error = client
            .db_query(DbQueryRequest {
                ciphertext,
                query: DbQueryPayload {
                    sql: "select missing_column from (select 1 as n) t".to_string(),
                    params: None,
                },
                options: Some(DbQueryOptions {
                    timeout_ms: Some(3000),
                    max_rows: Some(100),
                }),
            })
            .await
            .expect_err("query should fail");
        let body = assert_http_status(error, 422).expect("error body");
        let message = body["error"].as_str().unwrap_or_default();
        assert!(message.contains("database error ["));
        assert!(
            message.to_ascii_lowercase().contains("missing_column")
                || message.to_ascii_lowercase().contains("column")
        );

        instance
            .stop()
            .await
            .expect("embedded postgres should stop");
    }

    #[tokio::test]
    async fn db_query_supports_typed_jsonb_params() {
        let (instance, client, ciphertext) = make_db_fixture("", "read_write").await;

        let result = client
            .db_query(DbQueryRequest {
                ciphertext,
                query: DbQueryPayload {
                    sql: "select $1::jsonb->>'kind' as kind, $2::varchar as label".to_string(),
                    params: Some(vec![
                        TypedQueryParam::Json(json!({ "kind": "customer" })),
                        TypedQueryParam::Text("gold".to_string()),
                    ]),
                },
                options: None,
            })
            .await
            .expect("query should succeed");

        assert_eq!(result.row_count, 1);
        assert_eq!(result.rows[0][0].as_str(), Some("customer"));
        assert_eq!(result.rows[0][1].as_str(), Some("gold"));

        instance
            .stop()
            .await
            .expect("embedded postgres should stop");
    }

    #[tokio::test]
    async fn db_query_supports_typed_timestamptz_params() {
        let (instance, client, ciphertext) = make_db_fixture("", "read_write").await;

        let result = client
            .db_query(DbQueryRequest {
                ciphertext,
                query: DbQueryPayload {
                    sql: "select ($1::timestamptz at time zone 'UTC')::text as ts".to_string(),
                    params: Some(vec![TypedQueryParam::TimestampTz(
                        DateTime::<FixedOffset>::parse_from_rfc3339("2025-01-02T03:04:05+00:00")
                            .expect("timestamp should parse"),
                    )]),
                },
                options: None,
            })
            .await
            .expect("query should succeed");

        assert_eq!(result.row_count, 1);
        assert!(
            result.rows[0][0]
                .as_str()
                .unwrap_or_default()
                .starts_with("2025-01-02 03:04:05")
        );

        instance
            .stop()
            .await
            .expect("embedded postgres should stop");
    }

    #[tokio::test]
    async fn db_query_supports_typed_json_object_and_array_params() {
        let (instance, client, ciphertext) = make_db_fixture("", "read_write").await;

        let result = client
            .db_query(DbQueryRequest {
                ciphertext,
                query: DbQueryPayload {
                    sql: "select $1::jsonb->>'kind' as kind, jsonb_array_length($2::jsonb) as n"
                        .to_string(),
                    params: Some(vec![
                        TypedQueryParam::Json(json!({ "kind": "customer" })),
                        TypedQueryParam::Json(json!([1, 2, 3])),
                    ]),
                },
                options: None,
            })
            .await
            .expect("query should succeed");

        assert_eq!(result.row_count, 1);
        assert_eq!(result.rows[0][0].as_str(), Some("customer"));
        assert_eq!(result.rows[0][1].as_i64(), Some(3));

        instance
            .stop()
            .await
            .expect("embedded postgres should stop");
    }

    #[tokio::test]
    async fn db_query_preserves_select_column_order() {
        let (instance, client, ciphertext) = make_db_fixture("", "read_write").await;

        let result = client
            .db_query(DbQueryRequest {
                ciphertext,
                query: DbQueryPayload {
                    sql: "select 1 as z, 2 as a, 3 as m".to_string(),
                    params: None,
                },
                options: None,
            })
            .await
            .expect("query should succeed");

        assert_eq!(result.columns[0].name, "z");
        assert_eq!(result.columns[1].name, "a");
        assert_eq!(result.columns[2].name, "m");
        assert_eq!(result.rows[0][0].as_i64(), Some(1));
        assert_eq!(result.rows[0][1].as_i64(), Some(2));
        assert_eq!(result.rows[0][2].as_i64(), Some(3));

        instance
            .stop()
            .await
            .expect("embedded postgres should stop");
    }

    #[tokio::test]
    async fn db_query_binds_null_params_in_select() {
        let (instance, client, ciphertext) = make_db_fixture("", "read_write").await;

        let result = client
            .db_query(DbQueryRequest {
                ciphertext,
                query: DbQueryPayload {
                    sql: "select ($1::int) is null as n_null, ($2::text) is null as t_null, $3::int as present"
                        .to_string(),
                    params: Some(vec![
                        TypedQueryParam::Null,
                        TypedQueryParam::Null,
                        TypedQueryParam::Int32(5),
                    ]),
                },
                options: Some(DbQueryOptions {
                    timeout_ms: Some(3000),
                    max_rows: Some(100),
                }),
            })
            .await
            .expect("query should succeed");

        assert_eq!(result.row_count, 1);
        assert_eq!(result.rows[0][0].as_bool(), Some(true));
        assert_eq!(result.rows[0][1].as_bool(), Some(true));
        assert_eq!(result.rows[0][2].as_i64(), Some(5));

        instance
            .stop()
            .await
            .expect("embedded postgres should stop");
    }

    #[tokio::test]
    async fn db_query_inserts_null_into_nullable_columns() {
        let table = unique_table_name("svnb");
        let migration_sql = format!(
            "create table {} (id int primary key, n int null, t text null)",
            table
        );
        let (instance, client, ciphertext) = make_db_fixture(&migration_sql, "read_write").await;

        client
            .db_query(DbQueryRequest {
                ciphertext: clone_ciphertext(&ciphertext),
                query: DbQueryPayload {
                    sql: format!("insert into {} (id, n, t) values (1, $1, $2)", table),
                    params: Some(vec![TypedQueryParam::Null, TypedQueryParam::Null]),
                },
                options: Some(DbQueryOptions {
                    timeout_ms: Some(3000),
                    max_rows: Some(100),
                }),
            })
            .await
            .expect("insert nulls");

        let result = client
            .db_query(DbQueryRequest {
                ciphertext: clone_ciphertext(&ciphertext),
                query: DbQueryPayload {
                    sql: format!("select n, t from {} where id = 1", table),
                    params: None,
                },
                options: Some(DbQueryOptions {
                    timeout_ms: Some(3000),
                    max_rows: Some(100),
                }),
            })
            .await
            .expect("select row 1");
        assert_eq!(result.row_count, 1);
        assert!(result.rows[0][0].is_null());
        assert!(result.rows[0][1].is_null());

        client
            .db_query(DbQueryRequest {
                ciphertext: clone_ciphertext(&ciphertext),
                query: DbQueryPayload {
                    sql: format!("insert into {} (id, n, t) values (2, $1, $2)", table),
                    params: Some(vec![TypedQueryParam::Int32(42), TypedQueryParam::Null]),
                },
                options: Some(DbQueryOptions {
                    timeout_ms: Some(3000),
                    max_rows: Some(100),
                }),
            })
            .await
            .expect("insert mixed row");

        let result = client
            .db_query(DbQueryRequest {
                ciphertext,
                query: DbQueryPayload {
                    sql: format!("select n, t from {} where id = 2", table),
                    params: None,
                },
                options: Some(DbQueryOptions {
                    timeout_ms: Some(3000),
                    max_rows: Some(100),
                }),
            })
            .await
            .expect("select row 2");
        assert_eq!(result.row_count, 1);
        assert_eq!(result.rows[0][0].as_i64(), Some(42));
        assert!(result.rows[0][1].is_null());

        instance
            .stop()
            .await
            .expect("embedded postgres should stop");
    }

    #[tokio::test]
    async fn db_query_supports_all_typed_params_non_null() {
        let table = unique_table_name("svtypes");
        let migration_sql = format!(
            "create table {} (id int primary key, b boolean not null, i16 smallint not null, i32 integer not null, i64 bigint not null, f64 double precision not null, txt text not null, tstz timestamptz not null, ts timestamp not null, d date not null, tm time not null, u uuid not null, bts bytea not null, j json not null, jb jsonb not null)",
            table
        );
        let (instance, client, ciphertext) = make_db_fixture(&migration_sql, "read_write").await;

        client
            .db_query(DbQueryRequest {
                ciphertext: clone_ciphertext(&ciphertext),
                query: DbQueryPayload {
                    sql: format!(
                        "insert into {} (id, b, i16, i32, i64, f64, txt, tstz, ts, d, tm, u, bts, j, jb) values (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
                        table
                    ),
                    params: Some(vec![
                        TypedQueryParam::Bool(true),
                        TypedQueryParam::Int16(12),
                        TypedQueryParam::Int32(3456),
                        TypedQueryParam::Int(9_876_543_210_i64),
                        TypedQueryParam::Float(12.75),
                        TypedQueryParam::Text("hello-types".to_string()),
                        TypedQueryParam::TimestampTz(
                            DateTime::<FixedOffset>::parse_from_rfc3339(
                                "2025-01-02T03:04:05+00:00",
                            )
                            .expect("timestamp with timezone should parse"),
                        ),
                        TypedQueryParam::Timestamp(
                            NaiveDateTime::parse_from_str(
                                "2025-01-02T03:04:05",
                                "%Y-%m-%dT%H:%M:%S",
                            )
                            .expect("timestamp should parse"),
                        ),
                        TypedQueryParam::Date("2025-01-02".to_string()),
                        TypedQueryParam::Time("03:04:05".to_string()),
                        TypedQueryParam::Uuid(
                            "123e4567-e89b-12d3-a456-426614174000".to_string(),
                        ),
                        TypedQueryParam::Bytea("\\x68656c6c6f".to_string()),
                        TypedQueryParam::Json(json!({ "kind": "object", "n": 1 })),
                        TypedQueryParam::Json(json!([1, 2, 3])),
                    ]),
                },
                options: Some(DbQueryOptions {
                    timeout_ms: Some(3000),
                    max_rows: Some(100),
                }),
            })
            .await
            .expect("insert typed params");

        let result = client
            .db_query(DbQueryRequest {
                ciphertext,
                query: DbQueryPayload {
                    sql: format!(
                        "select b, i16, i32, i64, f64, txt, (tstz at time zone 'UTC')::text as tstz_utc, ts::text as ts_text, d::text as d_text, tm::text as tm_text, u::text as u_text, encode(bts, 'hex') as bts_hex, j, jb from {} where id = 1",
                        table
                    ),
                    params: None,
                },
                options: Some(DbQueryOptions {
                    timeout_ms: Some(3000),
                    max_rows: Some(100),
                }),
            })
            .await
            .expect("select typed params");

        let row = result.rows[0].as_slice();
        assert_eq!(row[0].as_bool(), Some(true));
        assert_eq!(row[1].as_i64(), Some(12));
        assert_eq!(row[2].as_i64(), Some(3456));
        assert_eq!(row[3].as_i64(), Some(9_876_543_210_i64));
        assert_eq!(row[4].as_f64(), Some(12.75));
        assert_eq!(row[5].as_str(), Some("hello-types"));
        assert!(
            row[6]
                .as_str()
                .unwrap_or_default()
                .starts_with("2025-01-02 03:04:05")
        );
        assert_eq!(row[7].as_str(), Some("2025-01-02 03:04:05"));
        assert_eq!(row[8].as_str(), Some("2025-01-02"));
        assert_eq!(row[9].as_str(), Some("03:04:05"));
        assert_eq!(
            row[10].as_str(),
            Some("123e4567-e89b-12d3-a456-426614174000")
        );
        assert_eq!(row[11].as_str(), Some("68656c6c6f"));
        assert_eq!(row[12]["kind"].as_str(), Some("object"));
        assert_eq!(row[12]["n"].as_i64(), Some(1));
        assert_eq!(row[13][0].as_i64(), Some(1));
        assert_eq!(row[13][1].as_i64(), Some(2));
        assert_eq!(row[13][2].as_i64(), Some(3));

        instance
            .stop()
            .await
            .expect("embedded postgres should stop");
    }

    #[tokio::test]
    async fn db_query_supports_all_typed_params_as_null_for_nullable_columns() {
        let table = unique_table_name("svnulltypes");
        let migration_sql = format!(
            "create table {} (id int primary key, b boolean null, i16 smallint null, i32 integer null, i64 bigint null, f64 double precision null, txt text null, tstz timestamptz null, ts timestamp null, d date null, tm time null, u uuid null, bts bytea null, j json null, jb jsonb null)",
            table
        );
        let (instance, client, ciphertext) = make_db_fixture(&migration_sql, "read_write").await;

        client
            .db_query(DbQueryRequest {
                ciphertext: clone_ciphertext(&ciphertext),
                query: DbQueryPayload {
                    sql: format!(
                        "insert into {} (id, b, i16, i32, i64, f64, txt, tstz, ts, d, tm, u, bts, j, jb) values (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
                        table
                    ),
                    params: Some(vec![
                        TypedQueryParam::Null,
                        TypedQueryParam::Null,
                        TypedQueryParam::Null,
                        TypedQueryParam::Null,
                        TypedQueryParam::Null,
                        TypedQueryParam::Null,
                        TypedQueryParam::Null,
                        TypedQueryParam::Null,
                        TypedQueryParam::Null,
                        TypedQueryParam::Null,
                        TypedQueryParam::Null,
                        TypedQueryParam::Null,
                        TypedQueryParam::Null,
                        TypedQueryParam::Null,
                    ]),
                },
                options: Some(DbQueryOptions {
                    timeout_ms: Some(3000),
                    max_rows: Some(100),
                }),
            })
            .await
            .expect("insert null typed params");

        let result = client
            .db_query(DbQueryRequest {
                ciphertext,
                query: DbQueryPayload {
                    sql: format!(
                        "select b, i16, i32, i64, f64, txt, tstz, ts, d, tm, u, bts, j, jb from {} where id = 1",
                        table
                    ),
                    params: None,
                },
                options: Some(DbQueryOptions {
                    timeout_ms: Some(3000),
                    max_rows: Some(100),
                }),
            })
            .await
            .expect("select nullable row");

        assert_eq!(result.row_count, 1);
        assert!(result.rows[0].iter().all(serde_json::Value::is_null));

        instance
            .stop()
            .await
            .expect("embedded postgres should stop");
    }
}
