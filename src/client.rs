use std::fmt::{Display, Formatter};

use async_trait::async_trait;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
#[cfg(any(test, feature = "test-utils"))]
use serde_json::json;
use serde_json::Value;

#[cfg(any(test, feature = "test-utils"))]
use crate::config::Config;
use crate::crypto::CipherText;
use crate::db_query::{DbQueryResult, TypedQueryParam};
use crate::proxy_substitute::{OutboundRequest, ProxySubstituteResponse};

#[derive(Debug, Clone)]
pub struct SimpleVaultClient<T: SimpleVaultTransport> {
    key_name: String,
    transport: T,
}

impl<T: SimpleVaultTransport> SimpleVaultClient<T> {
    pub fn new(key_name: impl Into<String>, transport: T) -> Self {
        Self {
            key_name: key_name.into(),
            transport,
        }
    }

    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    pub async fn encrypt(&self, plaintext: impl Into<String>) -> Result<CipherTextObject, ClientError> {
        self.transport
            .post_json(
                &self.key_name,
                "encrypt",
                EncryptRequest {
                    plaintext: plaintext.into(),
                },
            )
            .await
    }

    pub async fn decrypt(&self, ciphertext: CipherText) -> Result<PlainTextObject, ClientError> {
        self.transport
            .post_json(&self.key_name, "decrypt", CipherTextObject { ciphertext })
            .await
    }

    pub async fn rotate(&self, ciphertext: CipherText) -> Result<CipherTextObject, ClientError> {
        self.transport
            .post_json(&self.key_name, "rotate", CipherTextObject { ciphertext })
            .await
    }

    pub async fn create_signature(
        &self,
        request: CreateSignatureRequest,
    ) -> Result<CreateSignatureResponse, ClientError> {
        self.transport
            .post_json(&self.key_name, "create-signature", request)
            .await
    }

    pub async fn verify_signature(
        &self,
        request: VerifySignatureRequest,
    ) -> Result<VerifySignatureResponse, ClientError> {
        self.transport
            .post_json(&self.key_name, "verify-signature", request)
            .await
    }

    pub async fn proxy_substitute(
        &self,
        request: ProxySubstituteRequest,
    ) -> Result<ProxySubstituteResponse, ClientError> {
        self.transport
            .post_json(&self.key_name, "proxy-substitute", request)
            .await
    }

    pub async fn db_query(&self, request: DbQueryRequest) -> Result<DbQueryResult, ClientError> {
        self.transport
            .post_json(&self.key_name, "db-query", request)
            .await
    }

    pub async fn version(&self) -> Result<VersionResponse, ClientError> {
        self.transport.get_json(&self.key_name, "version").await
    }
}

impl SimpleVaultClient<HttpTransport> {
    pub fn with_http_transport(
        key_name: impl Into<String>,
        base_url: impl Into<String>,
        api_key: Option<String>,
    ) -> Self {
        Self::new(key_name, HttpTransport::new(base_url, api_key))
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl SimpleVaultClient<InMemoryTransport> {
    pub fn with_test_transport(config: Option<Value>) -> Result<Self, ClientError> {
        let config_value = config.unwrap_or_else(default_permissive_test_config);
        let parsed_config: Config =
            serde_json::from_value(config_value).map_err(ClientError::InvalidConfig)?;
        let app = crate::api::build_router(parsed_config);
        let transport = InMemoryTransport::new(app, None);
        Ok(Self::new("vault", transport))
    }
}

#[async_trait]
pub trait SimpleVaultTransport: Clone + Send + Sync + 'static {
    async fn send_json<B>(
        &self,
        method: HttpMethod,
        key_name: &str,
        endpoint: &str,
        body: Option<&B>,
    ) -> Result<Value, ClientError>
    where
        B: Serialize + Send + Sync;

    async fn post_json<B, R>(&self, key_name: &str, endpoint: &str, body: B) -> Result<R, ClientError>
    where
        B: Serialize + Send + Sync,
        R: for<'de> Deserialize<'de> + Send,
    {
        let value = self
            .send_json(HttpMethod::Post, key_name, endpoint, Some(&body))
            .await?;
        serde_json::from_value(value).map_err(ClientError::Deserialize)
    }

    async fn get_json<R>(&self, key_name: &str, endpoint: &str) -> Result<R, ClientError>
    where
        R: for<'de> Deserialize<'de> + Send,
    {
        let value = self
            .send_json::<serde_json::Value>(HttpMethod::Get, key_name, endpoint, None)
            .await?;
        serde_json::from_value(value).map_err(ClientError::Deserialize)
    }
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
            ClientError::Deserialize(error) => write!(f, "response deserialization error: {}", error),
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
    api_key: Option<String>,
    client: reqwest::Client,
}

impl HttpTransport {
    pub fn new(base_url: impl Into<String>, api_key: Option<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key,
            client: reqwest::Client::new(),
        }
    }

    fn url_for(&self, key_name: &str, endpoint: &str) -> String {
        let encoded_key_name: String = form_urlencoded::byte_serialize(key_name.as_bytes()).collect();
        format!("{}/v1/{}/{}", self.base_url, encoded_key_name, endpoint)
    }
}

#[async_trait]
impl SimpleVaultTransport for HttpTransport {
    async fn send_json<B>(
        &self,
        method: HttpMethod,
        key_name: &str,
        endpoint: &str,
        body: Option<&B>,
    ) -> Result<Value, ClientError>
    where
        B: Serialize + Send + Sync,
    {
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
            request = request.json(payload);
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
}

#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Clone)]
pub struct InMemoryTransport {
    app: axum::Router,
    api_key: Option<String>,
}

#[cfg(any(test, feature = "test-utils"))]
impl InMemoryTransport {
    pub fn new(app: axum::Router, api_key: Option<String>) -> Self {
        Self { app, api_key }
    }
}

#[cfg(any(test, feature = "test-utils"))]
#[async_trait]
impl SimpleVaultTransport for InMemoryTransport {
    async fn send_json<B>(
        &self,
        method: HttpMethod,
        key_name: &str,
        endpoint: &str,
        body: Option<&B>,
    ) -> Result<Value, ClientError>
    where
        B: Serialize + Send + Sync,
    {
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
                let body_string = serde_json::to_string(payload).map_err(ClientError::Serialize)?;
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
