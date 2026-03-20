use std::fmt::Debug;
use std::sync::Arc;

use crate::config::Config;
use crate::crypto::{CipherText, verify_signature_with_encrypted_secret_bytes};
use axum::{
    Json, Router,
    extract::{FromRequest, FromRequestParts, Path, Request, State, rejection::JsonRejection},
    http::{Request as HttpRequest, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use secrets::SecretVec;
use serde::de::{Deserializer, Error as SerdeError, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize)]
pub struct CipherTextObject {
    pub ciphertext: CipherText,
}

pub struct PlainTextObject {
    pub plaintext: SecretVec<u8>,
}

impl Debug for PlainTextObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlainTextObject")
            .field("plaintext", &"********")
            .finish()
    }
}

impl Serialize for PlainTextObject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut st = serializer.serialize_struct("PlainTextObject", 1)?;
        let bytes = self.plaintext.borrow();
        let text = std::str::from_utf8(bytes.as_ref()).map_err(|e| {
            serde::ser::Error::custom(format!("plaintext is not valid UTF-8: {}", e))
        })?;
        st.serialize_field("plaintext", text)?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for PlainTextObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PlainTextVisitor;

        impl<'de> Visitor<'de> for PlainTextVisitor {
            type Value = PlainTextObject;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "a struct {{ plaintext: <string> }}")
            }

            fn visit_map<A>(self, mut map: A) -> Result<PlainTextObject, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut plaintext_str: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "plaintext" {
                        if plaintext_str.is_some() {
                            return Err(SerdeError::duplicate_field("plaintext"));
                        }
                        plaintext_str = Some(map.next_value()?);
                    } else {
                        let _ = map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                let s = plaintext_str.ok_or_else(|| SerdeError::missing_field("plaintext"))?;
                let bytes = s.as_bytes();
                let len = bytes.len();
                let plaintext = SecretVec::new(len, |buf| buf.copy_from_slice(bytes));
                Ok(PlainTextObject { plaintext })
            }
        }

        deserializer.deserialize_struct("PlainTextObject", &["plaintext"], PlainTextVisitor)
    }
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
}

/// Stored in request extensions by auth middleware when API key auth succeeds.
#[derive(Clone)]
struct AuthenticatedKey(String);

/// Extractor that reads the authenticated API key from request extensions (set by auth middleware).
struct AuthenticatedKeyExt(Option<String>);

impl<S> FromRequestParts<S> for AuthenticatedKeyExt
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let key = parts
            .extensions
            .get::<AuthenticatedKey>()
            .map(|a| a.0.clone());
        Ok(AuthenticatedKeyExt(key))
    }
}

fn extract_api_key_from_request<B>(req: &HttpRequest<B>) -> Option<String> {
    if let Some(auth) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(s) = auth.to_str() {
            if let Some(key) = s.strip_prefix("Bearer ") {
                return Some(key.trim().to_string());
            }
        }
    }
    if let Some(x_api_key) = req.headers().get("x-api-key") {
        if let Ok(s) = x_api_key.to_str() {
            return Some(s.trim().to_string());
        }
    }
    if let Some(query) = req.uri().query() {
        for pair in form_urlencoded::parse(query.as_bytes()) {
            if pair.0 == "api_key" {
                return Some(pair.1.into_owned());
            }
        }
    }
    None
}

async fn auth_middleware(
    State(state): State<AppState>,
    mut request: HttpRequest<axum::body::Body>,
    next: Next,
) -> axum::response::Response {
    if !state.config.api_keys_required() {
        return next.run(request).await;
    }
    let key = extract_api_key_from_request(&request);
    match key {
        Some(k) if state.config.validate_api_key(&k) => {
            request.extensions_mut().insert(AuthenticatedKey(k));
            next.run(request).await
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "missing or invalid API key" })),
        )
            .into_response(),
    }
}

/// If API key auth is required, checks that the authenticated key is allowed for this key name and operation.
/// Returns Some(response) to return 403, or None to continue.
fn check_scope<F>(
    state: &AppState,
    key_str: Option<&str>,
    key_name: &str,
    operation_allowed: F,
) -> Option<Response>
where
    F: FnOnce(&crate::config::OperationsScope) -> bool,
{
    if !state.config.api_keys_required() {
        return None;
    }
    let key_str = key_str?;
    let api_key = state.config.get_matching_api_key(key_str)?;
    if !api_key.keys_scope().allows(key_name) {
        return Some(
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": "API key not allowed for this key" })),
            )
                .into_response(),
        );
    }
    if !operation_allowed(api_key.operations_scope()) {
        return Some(
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": "API key not allowed for this operation" })),
            )
                .into_response(),
        );
    }
    None
}

struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": self.0.to_string() })),
        )
            .into_response()
    }
}

impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        ApiError(err.into())
    }
}

/// JSON extractor that returns `{ "error": "..." }` on rejection (matches dev server).
struct ApiJsonRejection(JsonRejection);

impl IntoResponse for ApiJsonRejection {
    fn into_response(self) -> axum::response::Response {
        let status = self.0.status();
        let body = self.0.body_text();
        (status, Json(serde_json::json!({ "error": body }))).into_response()
    }
}

/// JSON extractor with JSON-formatted error responses.
#[derive(Debug, Clone, Copy)]
struct ApiJson<T>(T);

impl<T> std::ops::Deref for ApiJson<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, S> FromRequest<S> for ApiJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiJsonRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(inner)) => Ok(ApiJson(inner)),
            Err(rejection) => Err(ApiJsonRejection(rejection)),
        }
    }
}

#[derive(Deserialize)]
struct KeyNamePath {
    key_name: String,
}

#[derive(Deserialize)]
struct VerifySignatureRequest {
    ciphertext: CipherText,
    payload: String,
    signature: String,
    algorithm: String,
}

#[derive(Serialize)]
struct VerifySignatureResponse {
    verified: bool,
}

async fn encrypt_handler(
    Path(KeyNamePath { key_name }): Path<KeyNamePath>,
    State(state): State<AppState>,
    AuthenticatedKeyExt(mut auth_key): AuthenticatedKeyExt,
    ApiJson(body): ApiJson<PlainTextObject>,
) -> Response {
    if let Some(r) = check_scope(&state, auth_key.as_deref(), &key_name, |ops| {
        ops.allows_encrypt()
    }) {
        return r;
    }

    auth_key.zeroize();

    let (version, key) = match state.config.get_latest_key(&key_name) {
        Some(t) => t,
        None => return ApiError(anyhow::anyhow!("key not found: {}", key_name)).into_response(),
    };
    match CipherText::encrypt(body.plaintext, key, version) {
        Ok(ciphertext) => Json(CipherTextObject { ciphertext }).into_response(),
        Err(e) => ApiError(e.into()).into_response(),
    }
}

async fn decrypt_handler(
    Path(KeyNamePath { key_name }): Path<KeyNamePath>,
    State(state): State<AppState>,
    AuthenticatedKeyExt(mut auth_key): AuthenticatedKeyExt,
    ApiJson(body): ApiJson<CipherTextObject>,
) -> Response {
    if let Some(r) = check_scope(&state, auth_key.as_deref(), &key_name, |ops| {
        ops.allows_decrypt()
    }) {
        return r;
    }
    auth_key.zeroize();
    let key = match state.config.get_key(&key_name, body.ciphertext.key_version) {
        Some(k) => k,
        None => {
            return ApiError(anyhow::anyhow!(
                "key not found: {} (version {})",
                key_name,
                body.ciphertext.key_version
            ))
            .into_response();
        }
    };
    match body.ciphertext.decrypt(key) {
        Ok(plaintext) => Json(PlainTextObject { plaintext }).into_response(),
        Err(e) => ApiError(e.into()).into_response(),
    }
}

#[derive(Serialize)]
struct VersionResponse {
    version: u32,
}

async fn version_handler(
    Path(KeyNamePath { key_name }): Path<KeyNamePath>,
    State(state): State<AppState>,
) -> Result<Json<VersionResponse>, ApiError> {
    let (version, _) = state
        .config
        .get_latest_key(&key_name)
        .ok_or_else(|| anyhow::anyhow!("key not found: {}", key_name))?;
    Ok(Json(VersionResponse { version }))
}

async fn rotate_handler(
    Path(KeyNamePath { key_name }): Path<KeyNamePath>,
    State(state): State<AppState>,
    AuthenticatedKeyExt(mut auth_key): AuthenticatedKeyExt,
    ApiJson(body): ApiJson<CipherTextObject>,
) -> Response {
    if let Some(r) = check_scope(&state, auth_key.as_deref(), &key_name, |ops| {
        ops.allows_rotate()
    }) {
        return r;
    }
    auth_key.zeroize();
    let old_key = match state.config.get_key(&key_name, body.ciphertext.key_version) {
        Some(k) => k,
        None => {
            return ApiError(anyhow::anyhow!(
                "key not found: {} (version {})",
                key_name,
                body.ciphertext.key_version
            ))
            .into_response();
        }
    };
    let plaintext = match body.ciphertext.decrypt(old_key) {
        Ok(p) => p,
        Err(e) => return ApiError(e.into()).into_response(),
    };
    let (new_version, new_key) = match state.config.get_latest_key(&key_name) {
        Some(t) => t,
        None => return ApiError(anyhow::anyhow!("key not found: {}", key_name)).into_response(),
    };
    match CipherText::encrypt(plaintext, new_key, new_version) {
        Ok(ciphertext) => Json(CipherTextObject { ciphertext }).into_response(),
        Err(e) => ApiError(e.into()).into_response(),
    }
}

async fn verify_signature_handler(
    Path(KeyNamePath { key_name }): Path<KeyNamePath>,
    State(state): State<AppState>,
    AuthenticatedKeyExt(mut auth_key): AuthenticatedKeyExt,
    ApiJson(body): ApiJson<VerifySignatureRequest>,
) -> Response {
    if let Some(r) = check_scope(&state, auth_key.as_deref(), &key_name, |ops| {
        ops.allows_verify()
    }) {
        return r;
    }
    auth_key.zeroize();

    let key = match state.config.get_key(&key_name, body.ciphertext.key_version) {
        Some(k) => k,
        None => {
            return ApiError(anyhow::anyhow!(
                "key not found: {} (version {})",
                key_name,
                body.ciphertext.key_version
            ))
            .into_response();
        }
    };
    let payload_bytes = match hex::decode(body.payload.trim()) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "error": format!("payload must be hex-encoded: {}", e) })),
            )
                .into_response();
        }
    };
    let signature_bytes = match hex::decode(body.signature.trim()) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "error": format!("signature must be hex-encoded: {}", e) })),
            )
                .into_response();
        }
    };

    match verify_signature_with_encrypted_secret_bytes(
        &body.ciphertext,
        key,
        &payload_bytes,
        &signature_bytes,
        &body.algorithm,
    ) {
        Ok(verified) => Json(VerifySignatureResponse { verified }).into_response(),
        Err(e) => ApiError(e.into()).into_response(),
    }
}

fn build_router(config: Config) -> Router {
    let state = AppState {
        config: Arc::new(config),
    };
    Router::new()
        .route("/v1/{key_name}/encrypt", post(encrypt_handler))
        .route("/v1/{key_name}/decrypt", post(decrypt_handler))
        .route("/v1/{key_name}/rotate", post(rotate_handler))
        .route("/v1/{key_name}/verify-signature", post(verify_signature_handler))
        .route("/v1/{key_name}/version", get(version_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state)
}

pub async fn run_server(config: Config, port_override: Option<u16>) -> Result<(), anyhow::Error> {
    let server_port = port_override.unwrap_or(config.server_port);
    let app = build_router(config);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", server_port)).await?;
    println!(
        "SimpleVault server listening on http://0.0.0.0:{}",
        server_port
    );
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use secrets::SecretVec;
    use serde_json::json;
    use tower::ServiceExt;

    fn make_plaintext_object(s: &str) -> PlainTextObject {
        let bytes = s.as_bytes();
        let len = bytes.len();
        PlainTextObject {
            plaintext: SecretVec::new(len, |buf| buf.copy_from_slice(bytes)),
        }
    }

    #[test]
    fn test_serialize_plaintext_object() {
        let obj = make_plaintext_object("hello world");
        let json = serde_json::to_string(&obj).unwrap();
        assert_eq!(json, r#"{"plaintext":"hello world"}"#);
    }

    #[test]
    fn test_serialize_empty_string() {
        let obj = make_plaintext_object("");
        let json = serde_json::to_string(&obj).unwrap();
        assert_eq!(json, r#"{"plaintext":""}"#);
    }

    #[test]
    fn test_serialize_unicode() {
        let obj = make_plaintext_object("café 日本語 🎉");
        let json = serde_json::to_string(&obj).unwrap();
        assert_eq!(json, r#"{"plaintext":"café 日本語 🎉"}"#);
    }

    #[test]
    fn test_serialize_invalid_utf8_fails() {
        let invalid_utf8: Vec<u8> = vec![0xff, 0xfe, 0xfd];
        let obj = PlainTextObject {
            plaintext: SecretVec::new(invalid_utf8.len(), |buf| buf.copy_from_slice(&invalid_utf8)),
        };
        let result = serde_json::to_string(&obj);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("UTF-8"));
    }

    #[test]
    fn test_deserialize_plaintext_object() {
        let json = r#"{"plaintext":"hello world"}"#;
        let obj: PlainTextObject = serde_json::from_str(json).unwrap();
        assert_eq!(obj.plaintext.borrow().as_ref(), b"hello world");
    }

    #[test]
    fn test_deserialize_empty_string() {
        let json = r#"{"plaintext":""}"#;
        let obj: PlainTextObject = serde_json::from_str(json).unwrap();
        assert_eq!(obj.plaintext.borrow().as_ref(), b"");
    }

    #[test]
    fn test_deserialize_missing_field_fails() {
        let json = r#"{}"#;
        let result: Result<PlainTextObject, _> = serde_json::from_str(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("plaintext"));
    }

    #[test]
    fn test_deserialize_duplicate_field_fails() {
        let json = r#"{"plaintext":"a","plaintext":"b"}"#;
        let result: Result<PlainTextObject, _> = serde_json::from_str(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("duplicate"));
    }

    #[test]
    fn test_roundtrip_serialize_deserialize() {
        let original = make_plaintext_object("secret password 123");
        let json = serde_json::to_string(&original).unwrap();
        let restored: PlainTextObject = serde_json::from_str(&json).unwrap();
        assert_eq!(
            original.plaintext.borrow().as_ref(),
            restored.plaintext.borrow().as_ref()
        );
    }

    #[test]
    fn test_deserialize_ignores_extra_fields() {
        let json = r#"{"plaintext":"data","extra":"ignored","other":42}"#;
        let obj: PlainTextObject = serde_json::from_str(json).unwrap();
        assert_eq!(obj.plaintext.borrow().as_ref(), b"data");
    }

    // --- Test config helpers ---

    fn config_no_auth() -> Config {
        let json = r#"{
            "api_keys": [],
            "server_port": 8080,
            "keys": {
                "vault": {
                    "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                }
            }
        }"#;
        serde_json::from_str(json).unwrap()
    }

    fn config_with_auth(api_key: &str) -> Config {
        let json = format!(
            r#"{{
                "api_keys": ["{}"],
                "server_port": 8080,
                "keys": {{
                    "vault": {{
                        "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    }}
                }}
            }}"#,
            api_key
        );
        serde_json::from_str(&json).unwrap()
    }

    fn config_with_key_versions() -> Config {
        let json = r#"{
            "api_keys": [],
            "server_port": 8080,
            "keys": {
                "vault": {
                    "1": "0000000000000000000000000000000000000000000000000000000000000000",
                    "2": "1111111111111111111111111111111111111111111111111111111111111111"
                }
            }
        }"#;
        serde_json::from_str(json).unwrap()
    }

    fn config_without_vault_key() -> Config {
        let json = r#"{
            "api_keys": [],
            "server_port": 8080,
            "keys": {
                "other": {
                    "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                }
            }
        }"#;
        serde_json::from_str(json).unwrap()
    }

    /// Config with vault and other keys; one API key allowed only for key name "vault".
    fn config_with_keys_scope_vault_only() -> Config {
        let json = r#"{
            "api_keys": [{ "value": "vault-only-key", "keys": ["vault"], "operations": "all" }],
            "server_port": 8080,
            "keys": {
                "vault": { "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" },
                "other": { "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
            }
        }"#;
        serde_json::from_str(json).unwrap()
    }

    /// Config with one API key allowed only for operations encrypt and decrypt (no rotate).
    fn config_with_operations_encrypt_decrypt_only() -> Config {
        let json = r#"{
            "api_keys": [{ "value": "encrypt-decrypt-key", "keys": "all", "operations": ["encrypt", "decrypt"] }],
            "server_port": 8080,
            "keys": {
                "vault": { "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
            }
        }"#;
        serde_json::from_str(json).unwrap()
    }

    /// Config with one API key allowed only for key "other" and only encrypt.
    fn config_with_keys_other_operations_encrypt_only() -> Config {
        let json = r#"{
            "api_keys": [{ "value": "other-encrypt-key", "keys": ["other"], "operations": ["encrypt"] }],
            "server_port": 8080,
            "keys": {
                "vault": { "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" },
                "other": { "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
            }
        }"#;
        serde_json::from_str(json).unwrap()
    }

    /// Config with one API key allowed only for verify operation.
    fn config_with_operations_verify_only() -> Config {
        let json = r#"{
            "api_keys": [{ "value": "verify-only-key", "keys": "all", "operations": ["verify"] }],
            "server_port": 8080,
            "keys": {
                "vault": { "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
            }
        }"#;
        serde_json::from_str(json).unwrap()
    }

    async fn read_body(response: axum::response::Response) -> Vec<u8> {
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    // --- Auth middleware tests ---

    #[tokio::test]
    async fn auth_no_keys_required_allows_request() {
        let app = build_router(config_no_auth());
        let req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"plaintext":"hello"}"#))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_required_rejects_missing_key() {
        let app = build_router(config_with_auth("secret-key"));
        let req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"plaintext":"hello"}"#))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = read_body(response).await;
        let body_str = String::from_utf8(body).unwrap();
        assert!(body_str.contains("API key"));
    }

    #[tokio::test]
    async fn auth_required_rejects_invalid_key() {
        let app = build_router(config_with_auth("secret-key"));
        let req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("Authorization", "Bearer wrong-key")
            .body(Body::from(r#"{"plaintext":"hello"}"#))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_required_accepts_bearer_token() {
        let app = build_router(config_with_auth("secret-key"));
        let req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("Authorization", "Bearer secret-key")
            .body(Body::from(r#"{"plaintext":"hello"}"#))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_required_accepts_x_api_key_header() {
        let app = build_router(config_with_auth("secret-key"));
        let req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "secret-key")
            .body(Body::from(r#"{"plaintext":"hello"}"#))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_required_accepts_api_key_query_param() {
        let app = build_router(config_with_auth("secret-key"));
        let req = Request::post("/v1/vault/encrypt?api_key=secret-key")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"plaintext":"hello"}"#))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_bearer_trimmed_whitespace() {
        let app = build_router(config_with_auth("secret-key"));
        let req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("Authorization", "Bearer  secret-key ")
            .body(Body::from(r#"{"plaintext":"hello"}"#))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // --- Scope and operation enforcement tests ---

    #[tokio::test]
    async fn scope_keys_allows_only_listed_key_name() {
        let app = build_router(config_with_keys_scope_vault_only());

        let req_vault = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "vault-only-key")
            .body(Body::from(r#"{"plaintext":"hello"}"#))
            .unwrap();
        let resp_vault = app.clone().oneshot(req_vault).await.unwrap();
        assert_eq!(
            resp_vault.status(),
            StatusCode::OK,
            "encrypt to vault should be allowed"
        );

        let req_other = Request::post("/v1/other/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "vault-only-key")
            .body(Body::from(r#"{"plaintext":"hello"}"#))
            .unwrap();
        let resp_other = app.oneshot(req_other).await.unwrap();
        assert_eq!(resp_other.status(), StatusCode::FORBIDDEN);
        let body = read_body(resp_other).await;
        let body_str = String::from_utf8(body).unwrap();
        assert!(body_str.contains("not allowed for this key"));
    }

    #[tokio::test]
    async fn scope_operations_forbids_rotate_when_not_in_list() {
        let app = build_router(config_with_operations_encrypt_decrypt_only());

        let encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "encrypt-decrypt-key")
            .body(Body::from(r#"{"plaintext":"x"}"#))
            .unwrap();
        let encrypt_resp = app.clone().oneshot(encrypt_req).await.unwrap();
        assert_eq!(encrypt_resp.status(), StatusCode::OK);

        let body = read_body(encrypt_resp).await;
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ciphertext = parsed["ciphertext"].as_str().unwrap().to_string();

        let decrypt_req = Request::post("/v1/vault/decrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "encrypt-decrypt-key")
            .body(Body::from(json!({ "ciphertext": ciphertext }).to_string()))
            .unwrap();
        let decrypt_resp = app.clone().oneshot(decrypt_req).await.unwrap();
        assert_eq!(decrypt_resp.status(), StatusCode::OK);

        let rotate_req = Request::post("/v1/vault/rotate")
            .header("content-type", "application/json")
            .header("x-api-key", "encrypt-decrypt-key")
            .body(Body::from(json!({ "ciphertext": ciphertext }).to_string()))
            .unwrap();
        let rotate_resp = app.oneshot(rotate_req).await.unwrap();
        assert_eq!(rotate_resp.status(), StatusCode::FORBIDDEN);
        let rotate_body = read_body(rotate_resp).await;
        let rotate_str = String::from_utf8(rotate_body).unwrap();
        assert!(rotate_str.contains("not allowed for this operation"));
    }

    #[tokio::test]
    async fn scope_operations_forbids_decrypt_when_only_encrypt_allowed() {
        let app = build_router(config_with_keys_other_operations_encrypt_only());

        let encrypt_req = Request::post("/v1/other/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "other-encrypt-key")
            .body(Body::from(r#"{"plaintext":"x"}"#))
            .unwrap();
        let encrypt_resp = app.clone().oneshot(encrypt_req).await.unwrap();
        assert_eq!(encrypt_resp.status(), StatusCode::OK);

        let body = read_body(encrypt_resp).await;
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ciphertext = parsed["ciphertext"].as_str().unwrap().to_string();

        let decrypt_req = Request::post("/v1/other/decrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "other-encrypt-key")
            .body(Body::from(json!({ "ciphertext": ciphertext }).to_string()))
            .unwrap();
        let decrypt_resp = app.oneshot(decrypt_req).await.unwrap();
        assert_eq!(decrypt_resp.status(), StatusCode::FORBIDDEN);
        let dec_body = read_body(decrypt_resp).await;
        assert!(
            String::from_utf8(dec_body)
                .unwrap()
                .contains("not allowed for this operation")
        );
    }

    #[tokio::test]
    async fn scope_keys_forbids_vault_when_only_other_allowed() {
        let app = build_router(config_with_keys_other_operations_encrypt_only());

        let req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "other-encrypt-key")
            .body(Body::from(r#"{"plaintext":"hello"}"#))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = read_body(response).await;
        assert!(
            String::from_utf8(body)
                .unwrap()
                .contains("not allowed for this key")
        );
    }

    #[tokio::test]
    async fn scope_keys_and_operations_both_checked() {
        let app = build_router(config_with_keys_other_operations_encrypt_only());

        let req_other_encrypt = Request::post("/v1/other/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "other-encrypt-key")
            .body(Body::from(r#"{"plaintext":"ok"}"#))
            .unwrap();
        let resp = app.oneshot(req_other_encrypt).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn scope_operations_forbids_verify_when_not_in_list() {
        let app = build_router(config_with_operations_encrypt_decrypt_only());
        let req = Request::post("/v1/vault/verify-signature")
            .header("content-type", "application/json")
            .header("x-api-key", "encrypt-decrypt-key")
            .body(Body::from(
                r#"{"ciphertext":"v1:deadbeef:000000000000000000000000","payload":"78","signature":"aa","algorithm":"hmac-sha256"}"#,
            ))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // --- Encrypt handler tests ---

    #[tokio::test]
    async fn encrypt_returns_ciphertext() {
        let app = build_router(config_no_auth());
        let req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"plaintext":"hello world"}"#))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body(response).await;
        let body_str = String::from_utf8(body).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert!(parsed.get("ciphertext").is_some());
        let ct_str = parsed["ciphertext"].as_str().unwrap();
        assert!(ct_str.starts_with("v1:"));
    }

    #[tokio::test]
    async fn encrypt_empty_plaintext() {
        let app = build_router(config_no_auth());
        let req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"plaintext":""}"#))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn encrypt_key_not_found() {
        let app = build_router(config_without_vault_key());
        let req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"plaintext":"hello"}"#))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = read_body(response).await;
        let body_str = String::from_utf8(body).unwrap();
        assert!(body_str.contains("key not found"));
    }

    #[tokio::test]
    async fn encrypt_invalid_json() {
        let app = build_router(config_no_auth());
        let req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"plaintext"}"#))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert!(
            response.status() == StatusCode::BAD_REQUEST
                || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "invalid JSON should return 400 or 422, got {}",
            response.status()
        );
    }

    #[tokio::test]
    async fn encrypt_missing_plaintext_field() {
        let app = build_router(config_no_auth());
        let req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .body(Body::from(r#"{}"#))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    // --- Decrypt handler tests ---

    #[tokio::test]
    async fn decrypt_roundtrip() {
        let app = build_router(config_no_auth());
        let encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"plaintext":"secret message"}"#))
            .unwrap();
        let encrypt_resp = app.clone().oneshot(encrypt_req).await.unwrap();
        assert_eq!(encrypt_resp.status(), StatusCode::OK);
        let body = read_body(encrypt_resp).await;
        let body_str = String::from_utf8(body).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        let ciphertext = parsed["ciphertext"].as_str().unwrap().to_string();

        let decrypt_req = Request::post("/v1/vault/decrypt")
            .header("content-type", "application/json")
            .body(Body::from(json!({ "ciphertext": ciphertext }).to_string()))
            .unwrap();
        let decrypt_resp = app.oneshot(decrypt_req).await.unwrap();
        assert_eq!(decrypt_resp.status(), StatusCode::OK);
        let dec_body = read_body(decrypt_resp).await;
        let dec_parsed: serde_json::Value = serde_json::from_slice(&dec_body).unwrap();
        assert_eq!(dec_parsed["plaintext"].as_str().unwrap(), "secret message");
    }

    #[tokio::test]
    async fn decrypt_key_not_found() {
        let app = build_router(config_without_vault_key());
        let req = Request::post("/v1/vault/decrypt")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"ciphertext":"v1:deadbeef:000000000000000000000000"}"#,
            ))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = read_body(response).await;
        let body_str = String::from_utf8(body).unwrap();
        assert!(body_str.contains("key not found"));
    }

    #[tokio::test]
    async fn decrypt_invalid_ciphertext_format() {
        let app = build_router(config_no_auth());
        let req = Request::post("/v1/vault/decrypt")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"ciphertext":"invalid"}"#))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    // --- Verify signature handler tests ---

    #[tokio::test]
    async fn verify_signature_hmac_sha256_roundtrip() {
        let app = build_router(config_no_auth());

        let secret_encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"plaintext":"whsec_test_secret"}"#))
            .unwrap();
        let secret_encrypt_resp = app.clone().oneshot(secret_encrypt_req).await.unwrap();
        assert_eq!(secret_encrypt_resp.status(), StatusCode::OK);
        let secret_body = read_body(secret_encrypt_resp).await;
        let secret_parsed: serde_json::Value = serde_json::from_slice(&secret_body).unwrap();
        let ciphertext = secret_parsed["ciphertext"].as_str().unwrap().to_string();

        let payload = "{\"id\":\"evt_test\"}";
        let payload_hex = hex::encode(payload.as_bytes());
        let signature = {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"whsec_test_secret").unwrap();
            mac.update(payload.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        };

        let verify_req = Request::post("/v1/vault/verify-signature")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "payload": payload_hex,
                    "signature": signature,
                    "algorithm": "hmac-sha256"
                })
                .to_string(),
            ))
            .unwrap();
        let verify_resp = app.oneshot(verify_req).await.unwrap();
        assert_eq!(verify_resp.status(), StatusCode::OK);
        let verify_body = read_body(verify_resp).await;
        let verify_parsed: serde_json::Value = serde_json::from_slice(&verify_body).unwrap();
        assert_eq!(verify_parsed["verified"], true);
    }

    #[tokio::test]
    async fn verify_signature_returns_false_for_mismatch() {
        let app = build_router(config_no_auth());

        let secret_encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"plaintext":"whsec_test_secret"}"#))
            .unwrap();
        let secret_encrypt_resp = app.clone().oneshot(secret_encrypt_req).await.unwrap();
        assert_eq!(secret_encrypt_resp.status(), StatusCode::OK);
        let secret_body = read_body(secret_encrypt_resp).await;
        let secret_parsed: serde_json::Value = serde_json::from_slice(&secret_body).unwrap();
        let ciphertext = secret_parsed["ciphertext"].as_str().unwrap().to_string();

        let verify_req = Request::post("/v1/vault/verify-signature")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "payload": "7061796c6f6164",
                    "signature": "abcd",
                    "algorithm": "hmac-sha256"
                })
                .to_string(),
            ))
            .unwrap();
        let verify_resp = app.oneshot(verify_req).await.unwrap();
        assert_eq!(verify_resp.status(), StatusCode::OK);
        let verify_body = read_body(verify_resp).await;
        let verify_parsed: serde_json::Value = serde_json::from_slice(&verify_body).unwrap();
        assert_eq!(verify_parsed["verified"], false);
    }

    #[tokio::test]
    async fn verify_signature_rejects_non_hex_payload() {
        let app = build_router(config_no_auth());

        let secret_encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"plaintext":"whsec_test_secret"}"#))
            .unwrap();
        let secret_encrypt_resp = app.clone().oneshot(secret_encrypt_req).await.unwrap();
        assert_eq!(secret_encrypt_resp.status(), StatusCode::OK);
        let secret_body = read_body(secret_encrypt_resp).await;
        let secret_parsed: serde_json::Value = serde_json::from_slice(&secret_body).unwrap();
        let ciphertext = secret_parsed["ciphertext"].as_str().unwrap().to_string();

        let verify_req = Request::post("/v1/vault/verify-signature")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "payload": "not-hex",
                    "signature": "abcd",
                    "algorithm": "hmac-sha256"
                })
                .to_string(),
            ))
            .unwrap();
        let verify_resp = app.oneshot(verify_req).await.unwrap();
        assert_eq!(verify_resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn verify_signature_rejects_non_hex_signature() {
        let app = build_router(config_no_auth());

        let secret_encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"plaintext":"whsec_test_secret"}"#))
            .unwrap();
        let secret_encrypt_resp = app.clone().oneshot(secret_encrypt_req).await.unwrap();
        assert_eq!(secret_encrypt_resp.status(), StatusCode::OK);
        let secret_body = read_body(secret_encrypt_resp).await;
        let secret_parsed: serde_json::Value = serde_json::from_slice(&secret_body).unwrap();
        let ciphertext = secret_parsed["ciphertext"].as_str().unwrap().to_string();

        let verify_req = Request::post("/v1/vault/verify-signature")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "payload": "7061796c6f6164",
                    "signature": "not-hex",
                    "algorithm": "hmac-sha256"
                })
                .to_string(),
            ))
            .unwrap();
        let verify_resp = app.oneshot(verify_req).await.unwrap();
        assert_eq!(verify_resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn verify_signature_requires_verify_scope() {
        let app = build_router(config_with_operations_verify_only());

        let secret_encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "verify-only-key")
            .body(Body::from(r#"{"plaintext":"secret"}"#))
            .unwrap();
        let secret_encrypt_resp = app.clone().oneshot(secret_encrypt_req).await.unwrap();
        assert_eq!(secret_encrypt_resp.status(), StatusCode::FORBIDDEN);

        let key_only_encrypt_app = build_router(config_with_operations_encrypt_decrypt_only());
        let verify_req = Request::post("/v1/vault/verify-signature")
            .header("content-type", "application/json")
            .header("x-api-key", "encrypt-decrypt-key")
            .body(Body::from(
                r#"{"ciphertext":"v1:deadbeef:000000000000000000000000","payload":"78","signature":"aa","algorithm":"hmac-sha256"}"#,
            ))
            .unwrap();
        let verify_resp = key_only_encrypt_app.oneshot(verify_req).await.unwrap();
        assert_eq!(verify_resp.status(), StatusCode::FORBIDDEN);
    }

    // --- Version handler tests ---

    #[tokio::test]
    async fn version_returns_latest() {
        let app = build_router(config_with_key_versions());
        let req = Request::get("/v1/vault/version")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body(response).await;
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["version"].as_u64().unwrap(), 2);
    }

    #[tokio::test]
    async fn version_returns_one_when_single_version() {
        let app = build_router(config_no_auth());
        let req = Request::get("/v1/vault/version")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body(response).await;
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["version"].as_u64().unwrap(), 1);
    }

    #[tokio::test]
    async fn version_key_not_found() {
        let app = build_router(config_without_vault_key());
        let req = Request::get("/v1/vault/version")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = read_body(response).await;
        let body_str = String::from_utf8(body).unwrap();
        assert!(body_str.contains("key not found"));
    }

    // --- Rotate handler tests ---

    #[tokio::test]
    async fn rotate_reencrypts_with_latest_key() {
        let config_v1_only = {
            let json = r#"{
                "api_keys": [],
                "server_port": 8080,
                "keys": {
                    "vault": {
                        "1": "0000000000000000000000000000000000000000000000000000000000000000"
                    }
                }
            }"#;
            serde_json::from_str::<Config>(json).unwrap()
        };
        let app_v1 = build_router(config_v1_only);
        let encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"plaintext":"data to rotate"}"#))
            .unwrap();
        let encrypt_resp = app_v1.oneshot(encrypt_req).await.unwrap();
        assert_eq!(encrypt_resp.status(), StatusCode::OK);
        let body = read_body(encrypt_resp).await;
        let body_str = String::from_utf8(body).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        let ciphertext = parsed["ciphertext"].as_str().unwrap().to_string();
        assert!(
            ciphertext.contains("v1:"),
            "should be encrypted with version 1"
        );

        let app_v1_v2 = build_router(config_with_key_versions());
        let rotate_req = Request::post("/v1/vault/rotate")
            .header("content-type", "application/json")
            .body(Body::from(json!({ "ciphertext": ciphertext }).to_string()))
            .unwrap();
        let rotate_resp = app_v1_v2.clone().oneshot(rotate_req).await.unwrap();
        assert_eq!(rotate_resp.status(), StatusCode::OK);
        let rot_body = read_body(rotate_resp).await;
        let rot_parsed: serde_json::Value = serde_json::from_slice(&rot_body).unwrap();
        let new_ct = rot_parsed["ciphertext"].as_str().unwrap();
        assert!(
            new_ct.contains("v2:"),
            "should be re-encrypted with version 2"
        );

        let decrypt_req = Request::post("/v1/vault/decrypt")
            .header("content-type", "application/json")
            .body(Body::from(json!({ "ciphertext": new_ct }).to_string()))
            .unwrap();
        let decrypt_resp = app_v1_v2.oneshot(decrypt_req).await.unwrap();
        assert_eq!(decrypt_resp.status(), StatusCode::OK);
        let dec_body = read_body(decrypt_resp).await;
        let dec_parsed: serde_json::Value = serde_json::from_slice(&dec_body).unwrap();
        assert_eq!(dec_parsed["plaintext"].as_str().unwrap(), "data to rotate");
    }

    #[tokio::test]
    async fn rotate_key_not_found() {
        let app = build_router(config_without_vault_key());
        let req = Request::post("/v1/vault/rotate")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"ciphertext":"v1:deadbeef:000000000000000000000000"}"#,
            ))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // --- Routing tests ---

    #[tokio::test]
    async fn not_found_for_unknown_path() {
        let app = build_router(config_no_auth());
        let req = Request::get("/v1/vault/unknown")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn version_requires_get() {
        let app = build_router(config_no_auth());
        let req = Request::post("/v1/vault/version")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn encrypt_requires_post() {
        let app = build_router(config_no_auth());
        let req = Request::get("/v1/vault/encrypt")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    // --- CipherTextObject serialization tests ---

    #[test]
    fn ciphertext_object_serialize_deserialize() {
        let key = config_no_auth();
        let (_, enc_key) = key.get_latest_key("vault").unwrap();
        let plaintext = make_plaintext_object("test");
        let ct = CipherText::encrypt(plaintext.plaintext, enc_key, 1).unwrap();
        let obj = CipherTextObject { ciphertext: ct };
        let json = serde_json::to_string(&obj).unwrap();
        assert!(json.contains("ciphertext"));
        let restored: CipherTextObject = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.ciphertext.key_version, 1);
    }
}
