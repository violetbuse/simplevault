use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::crypto::{
    CipherText, create_signature_with_encrypted_secret_bytes,
    verify_signature_with_encrypted_secret_bytes,
};
use crate::db_query;
use crate::proxy_substitute;
use axum::{
    Json, Router,
    extract::{FromRequest, FromRequestParts, Path, Request, State, rejection::JsonRejection},
    http::{Request as HttpRequest, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use secrecy::{ExposeSecret, SecretSlice};
use serde::de::{Deserializer, Error as SerdeError, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize)]
pub struct CipherTextObject {
    pub ciphertext: CipherText,
}

pub struct PlainTextObject {
    pub plaintext: SecretSlice<u8>,
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
        let bytes = self.plaintext.expose_secret();
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
                let plaintext = SecretSlice::from(s.into_bytes());
                Ok(PlainTextObject { plaintext })
            }
        }

        deserializer.deserialize_struct("PlainTextObject", &["plaintext"], PlainTextVisitor)
    }
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    http_client: reqwest::Client,
    db_pool_cache: db_query::DbPoolCache,
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

#[derive(Deserialize)]
struct CreateSignatureRequest {
    ciphertext: CipherText,
    payload: String,
    algorithm: String,
}

#[derive(Serialize)]
struct CreateSignatureResponse {
    signature: String,
}

#[derive(Deserialize)]
struct DbQueryRequest {
    ciphertext: CipherText,
    query: DbQueryPayload,
    #[serde(default)]
    options: Option<DbQueryOptions>,
}

#[derive(Deserialize)]
struct DbQueryPayload {
    sql: String,
    #[serde(default)]
    params: Option<Vec<db_query::TypedQueryParam>>,
}

#[derive(Deserialize)]
struct DbQueryOptions {
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    max_rows: Option<usize>,
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
                Json(
                    serde_json::json!({ "error": format!("signature must be hex-encoded: {}", e) }),
                ),
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

async fn create_signature_handler(
    Path(KeyNamePath { key_name }): Path<KeyNamePath>,
    State(state): State<AppState>,
    AuthenticatedKeyExt(mut auth_key): AuthenticatedKeyExt,
    ApiJson(body): ApiJson<CreateSignatureRequest>,
) -> Response {
    if let Some(r) = check_scope(&state, auth_key.as_deref(), &key_name, |ops| {
        ops.allows_sign()
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

    match create_signature_with_encrypted_secret_bytes(
        &body.ciphertext,
        key,
        &payload_bytes,
        &body.algorithm,
    ) {
        Ok(signature) => Json(CreateSignatureResponse {
            signature: hex::encode(signature),
        })
        .into_response(),
        Err(e) => ApiError(e.into()).into_response(),
    }
}

async fn db_query_handler(
    Path(KeyNamePath { key_name }): Path<KeyNamePath>,
    State(state): State<AppState>,
    AuthenticatedKeyExt(mut auth_key): AuthenticatedKeyExt,
    ApiJson(body): ApiJson<DbQueryRequest>,
) -> Response {
    if let Some(r) = check_scope(&state, auth_key.as_deref(), &key_name, |ops| {
        ops.allows_db_query()
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
    let plaintext = match body.ciphertext.decrypt(key) {
        Ok(value) => value,
        Err(error) => return ApiError(error).into_response(),
    };
    let mut connection_string = match std::str::from_utf8(plaintext.expose_secret()) {
        Ok(value) => value.to_string(),
        Err(error) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "error": format!("decrypted plaintext is not valid UTF-8: {}", error) })),
            )
                .into_response();
        }
    };

    let targets = match db_query::parse_connection_targets(&connection_string) {
        Ok(value) => value,
        Err(error) => {
            db_query::sanitize_connection_string(&mut connection_string);
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "error": format!("invalid database connection string: {}", error) })),
            )
                .into_response();
        }
    };
    let requires_write = db_query::sql_requires_write(&body.query.sql);
    for (host, port) in &targets {
        if !state
            .config
            .db_destination_allows_query(&key_name, host, *port, requires_write)
        {
            db_query::sanitize_connection_string(&mut connection_string);
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": "database destination is not allowed for this key set or query type" })),
            )
                .into_response();
        }
    }

    let connection_hash = db_query::connection_string_hash(&connection_string);
    let pool = match state
        .db_pool_cache
        .get_or_create_pool(&connection_hash, &connection_string)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            db_query::sanitize_connection_string(&mut connection_string);
            return ApiError(error).into_response();
        }
    };
    db_query::sanitize_connection_string(&mut connection_string);

    let timeout_ms = body
        .options
        .as_ref()
        .and_then(|value| value.timeout_ms)
        .unwrap_or(db_query::DEFAULT_TIMEOUT_MS)
        .clamp(100, 60_000);
    let max_rows = body
        .options
        .as_ref()
        .and_then(|value| value.max_rows)
        .unwrap_or(db_query::DEFAULT_MAX_ROWS)
        .clamp(1, 10_000);
    let params = body.query.params.unwrap_or_default();

    match db_query::run_query(&pool, &body.query.sql, &params, timeout_ms, max_rows).await {
        Ok(result) => Json(result).into_response(),
        Err(error) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}

async fn proxy_substitute_handler(
    Path(KeyNamePath { key_name }): Path<KeyNamePath>,
    State(state): State<AppState>,
    AuthenticatedKeyExt(mut auth_key): AuthenticatedKeyExt,
    ApiJson(body): ApiJson<proxy_substitute::ProxySubstituteRequest>,
) -> Response {
    if let Some(r) = check_scope(&state, auth_key.as_deref(), &key_name, |ops| {
        ops.allows_proxy()
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
    let plaintext = match body.ciphertext.decrypt(key) {
        Ok(p) => p,
        Err(e) => return ApiError(e.into()).into_response(),
    };
    let plaintext_str = match std::str::from_utf8(plaintext.expose_secret()) {
        Ok(value) => value.to_string(),
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "error": format!("decrypted plaintext is not valid UTF-8: {}", e) })),
            )
                .into_response();
        }
    };

    let prepared = match proxy_substitute::prepare_outbound_request(
        body.request,
        &plaintext_str,
        body.placeholder.as_deref(),
    ) {
        Ok(value) => value,
        Err(error) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "error": error })),
            )
                .into_response();
        }
    };

    if let Err((status, error)) = proxy_substitute::validate_destination_safety(&prepared.url) {
        return (status, Json(serde_json::json!({ "error": error }))).into_response();
    }

    let host = match prepared.url.host_str() {
        Some(value) => value,
        None => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "error": "outbound url must include a host" })),
            )
                .into_response();
        }
    };
    if !state.config.destination_allowed(
        &key_name,
        prepared.method.as_str(),
        host,
        prepared.url.path(),
    ) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "destination is not allowed for this key set" })),
        )
            .into_response();
    }

    match proxy_substitute::execute_outbound_request(&state.http_client, prepared).await {
        Ok(proxy_response) => (
            StatusCode::from_u16(proxy_response.status).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(proxy_response),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": format!("upstream request failed: {}", error) })),
        )
            .into_response(),
    }
}

fn build_router(config: Config) -> Router {
    let state = AppState {
        config: Arc::new(config),
        http_client: reqwest::Client::new(),
        db_pool_cache: db_query::DbPoolCache::new(Duration::from_secs(60), Duration::from_secs(5)),
    };
    Router::new()
        .route("/v1/{key_name}/encrypt", post(encrypt_handler))
        .route("/v1/{key_name}/decrypt", post(decrypt_handler))
        .route("/v1/{key_name}/rotate", post(rotate_handler))
        .route(
            "/v1/{key_name}/create-signature",
            post(create_signature_handler),
        )
        .route(
            "/v1/{key_name}/verify-signature",
            post(verify_signature_handler),
        )
        .route(
            "/v1/{key_name}/proxy-substitute",
            post(proxy_substitute_handler),
        )
        .route("/v1/{key_name}/db-query", post(db_query_handler))
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
    use secrecy::{ExposeSecret, SecretSlice};
    use serde_json::json;
    use tower::ServiceExt;

    fn make_plaintext_object(s: &str) -> PlainTextObject {
        PlainTextObject {
            plaintext: SecretSlice::from(s.as_bytes().to_vec()),
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
            plaintext: SecretSlice::from(invalid_utf8),
        };
        let result = serde_json::to_string(&obj);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("UTF-8"));
    }

    #[test]
    fn test_deserialize_plaintext_object() {
        let json = r#"{"plaintext":"hello world"}"#;
        let obj: PlainTextObject = serde_json::from_str(json).unwrap();
        assert_eq!(obj.plaintext.expose_secret(), b"hello world".as_slice());
    }

    #[test]
    fn test_deserialize_empty_string() {
        let json = r#"{"plaintext":""}"#;
        let obj: PlainTextObject = serde_json::from_str(json).unwrap();
        assert_eq!(obj.plaintext.expose_secret(), b"".as_slice());
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
            original.plaintext.expose_secret(),
            restored.plaintext.expose_secret()
        );
    }

    #[test]
    fn test_deserialize_ignores_extra_fields() {
        let json = r#"{"plaintext":"data","extra":"ignored","other":42}"#;
        let obj: PlainTextObject = serde_json::from_str(json).unwrap();
        assert_eq!(obj.plaintext.expose_secret(), b"data".as_slice());
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

    /// Config with one API key allowed only for sign operation.
    fn config_with_operations_sign_only() -> Config {
        let json = r#"{
            "api_keys": [{ "value": "sign-only-key", "keys": "all", "operations": ["sign"] }],
            "server_port": 8080,
            "keys": {
                "vault": { "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
            }
        }"#;
        serde_json::from_str(json).unwrap()
    }

    /// Config with one API key allowed only for db_query operation.
    fn config_with_operations_db_query_only() -> Config {
        let json = r#"{
            "api_keys": [{ "value": "db-query-only-key", "keys": "all", "operations": ["db_query"] }],
            "server_port": 8080,
            "keys": {
                "vault": { "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
            }
        }"#;
        serde_json::from_str(json).unwrap()
    }

    fn config_with_db_destinations_for_vault() -> Config {
        let json = r#"{
            "api_keys": [{ "value": "db-query-key", "keys": "all", "operations": ["db_query", "encrypt"] }],
            "server_port": 8080,
            "keys": {
                "vault": { "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
            },
            "db_destinations": {
                "vault": [
                    { "host": "db-allowed.internal", "port": 5432 }
                ]
            }
        }"#;
        serde_json::from_str(json).unwrap()
    }

    fn config_with_db_read_only_destinations_for_vault() -> Config {
        let json = r#"{
            "api_keys": [{ "value": "db-query-key", "keys": "all", "operations": ["db_query", "encrypt"] }],
            "server_port": 8080,
            "keys": {
                "vault": { "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
            },
            "db_destinations": {
                "vault": [
                    { "host": "db-allowed.internal", "port": 5432, "access": "read_only" }
                ]
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

    #[tokio::test]
    async fn scope_operations_forbids_sign_when_not_in_list() {
        let app = build_router(config_with_operations_encrypt_decrypt_only());
        let req = Request::post("/v1/vault/create-signature")
            .header("content-type", "application/json")
            .header("x-api-key", "encrypt-decrypt-key")
            .body(Body::from(
                r#"{"ciphertext":"v1:deadbeef:000000000000000000000000","payload":"78","algorithm":"hmac-sha256"}"#,
            ))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn scope_operations_forbids_proxy_when_not_in_list() {
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

        let req = Request::post("/v1/vault/proxy-substitute")
            .header("content-type", "application/json")
            .header("x-api-key", "encrypt-decrypt-key")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "request": { "method": "GET", "url": "https://api.stripe.com/v1/charges" }
                })
                .to_string(),
            ))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn scope_operations_forbids_db_query_when_not_in_list() {
        let app = build_router(config_with_operations_encrypt_decrypt_only());
        let encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "encrypt-decrypt-key")
            .body(Body::from(
                r#"{"plaintext":"postgres://u:p@db.internal:5432/app"}"#,
            ))
            .unwrap();
        let encrypt_resp = app.clone().oneshot(encrypt_req).await.unwrap();
        assert_eq!(encrypt_resp.status(), StatusCode::OK);
        let body = read_body(encrypt_resp).await;
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ciphertext = parsed["ciphertext"].as_str().unwrap().to_string();

        let req = Request::post("/v1/vault/db-query")
            .header("content-type", "application/json")
            .header("x-api-key", "encrypt-decrypt-key")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "query": { "sql": "select 1" }
                })
                .to_string(),
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

    // --- Create signature handler tests ---

    #[tokio::test]
    async fn create_signature_hmac_sha256_roundtrip() {
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
        let expected_signature = {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"whsec_test_secret").unwrap();
            mac.update(payload.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        };

        let create_req = Request::post("/v1/vault/create-signature")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "payload": payload_hex,
                    "algorithm": "hmac-sha256"
                })
                .to_string(),
            ))
            .unwrap();
        let create_resp = app.oneshot(create_req).await.unwrap();
        assert_eq!(create_resp.status(), StatusCode::OK);
        let create_body = read_body(create_resp).await;
        let create_parsed: serde_json::Value = serde_json::from_slice(&create_body).unwrap();
        assert_eq!(
            create_parsed["signature"].as_str().unwrap(),
            expected_signature
        );
    }

    #[tokio::test]
    async fn create_signature_rejects_non_hex_payload() {
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

        let create_req = Request::post("/v1/vault/create-signature")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "payload": "not-hex",
                    "algorithm": "hmac-sha256"
                })
                .to_string(),
            ))
            .unwrap();
        let create_resp = app.oneshot(create_req).await.unwrap();
        assert_eq!(create_resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn create_signature_requires_sign_scope() {
        let app = build_router(config_with_operations_sign_only());

        let secret_encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "sign-only-key")
            .body(Body::from(r#"{"plaintext":"secret"}"#))
            .unwrap();
        let secret_encrypt_resp = app.clone().oneshot(secret_encrypt_req).await.unwrap();
        assert_eq!(secret_encrypt_resp.status(), StatusCode::FORBIDDEN);

        let key_only_encrypt_app = build_router(config_with_operations_encrypt_decrypt_only());
        let create_req = Request::post("/v1/vault/create-signature")
            .header("content-type", "application/json")
            .header("x-api-key", "encrypt-decrypt-key")
            .body(Body::from(
                r#"{"ciphertext":"v1:deadbeef:000000000000000000000000","payload":"78","algorithm":"hmac-sha256"}"#,
            ))
            .unwrap();
        let create_resp = key_only_encrypt_app.oneshot(create_req).await.unwrap();
        assert_eq!(create_resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_signature_rejects_unknown_algorithm() {
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

        let create_req = Request::post("/v1/vault/create-signature")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "payload": "7061796c6f6164",
                    "algorithm": "rsa-sha256"
                })
                .to_string(),
            ))
            .unwrap();
        let create_resp = app.oneshot(create_req).await.unwrap();
        assert_eq!(create_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
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

    #[tokio::test]
    async fn db_query_rejects_disallowed_destination() {
        let app = build_router(config_with_db_destinations_for_vault());
        let encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                r#"{"plaintext":"postgres://user:pass@db-blocked.internal:5432/app"}"#,
            ))
            .unwrap();
        let encrypt_resp = app.clone().oneshot(encrypt_req).await.unwrap();
        assert_eq!(encrypt_resp.status(), StatusCode::OK);
        let body = read_body(encrypt_resp).await;
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ciphertext = parsed["ciphertext"].as_str().unwrap().to_string();

        let req = Request::post("/v1/vault/db-query")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "query": { "sql": "select 1" }
                })
                .to_string(),
            ))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn db_query_allows_when_destination_policy_missing_for_key_name() {
        let app = build_router(config_with_operations_db_query_only());
        let encrypt_app = build_router(config_no_auth());
        let encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"plaintext":"postgres://user:pass@db.internal:5432/app"}"#,
            ))
            .unwrap();
        let encrypt_resp = encrypt_app.oneshot(encrypt_req).await.unwrap();
        assert_eq!(encrypt_resp.status(), StatusCode::OK);
        let body = read_body(encrypt_resp).await;
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ciphertext = parsed["ciphertext"].as_str().unwrap().to_string();

        let req = Request::post("/v1/vault/db-query")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-only-key")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "query": { "sql": "select 1" },
                    "options": { "timeout_ms": 200 }
                })
                .to_string(),
            ))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_ne!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn db_query_read_only_destination_allows_read_queries() {
        let app = build_router(config_with_db_read_only_destinations_for_vault());
        let encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                r#"{"plaintext":"postgres://user:pass@db-allowed.internal:5432/app"}"#,
            ))
            .unwrap();
        let encrypt_resp = app.clone().oneshot(encrypt_req).await.unwrap();
        assert_eq!(encrypt_resp.status(), StatusCode::OK);
        let body = read_body(encrypt_resp).await;
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ciphertext = parsed["ciphertext"].as_str().unwrap().to_string();

        let req = Request::post("/v1/vault/db-query")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "query": { "sql": "select 1" },
                    "options": { "timeout_ms": 200 }
                })
                .to_string(),
            ))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_ne!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn db_query_read_only_destination_rejects_write_queries() {
        let app = build_router(config_with_db_read_only_destinations_for_vault());
        let encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                r#"{"plaintext":"postgres://user:pass@db-allowed.internal:5432/app"}"#,
            ))
            .unwrap();
        let encrypt_resp = app.clone().oneshot(encrypt_req).await.unwrap();
        assert_eq!(encrypt_resp.status(), StatusCode::OK);
        let body = read_body(encrypt_resp).await;
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ciphertext = parsed["ciphertext"].as_str().unwrap().to_string();

        let req = Request::post("/v1/vault/db-query")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "query": { "sql": "create table blocked_write_test (id int)" }
                })
                .to_string(),
            ))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn db_query_read_only_destination_rejects_writable_cte_queries() {
        let app = build_router(config_with_db_read_only_destinations_for_vault());
        let encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                r#"{"plaintext":"postgres://user:pass@db-allowed.internal:5432/app"}"#,
            ))
            .unwrap();
        let encrypt_resp = app.clone().oneshot(encrypt_req).await.unwrap();
        assert_eq!(encrypt_resp.status(), StatusCode::OK);
        let body = read_body(encrypt_resp).await;
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ciphertext = parsed["ciphertext"].as_str().unwrap().to_string();

        let req = Request::post("/v1/vault/db-query")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "query": {
                        "sql": "with deleted as (delete from t where false returning *) select * from deleted"
                    }
                })
                .to_string(),
            ))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn db_query_executes_against_real_postgres_when_enabled() {
        if std::env::var("SIMPLEVAULT_ENABLE_DB_TESTS").unwrap_or_default() != "1" {
            return;
        }
        let connection_string = std::env::var("SIMPLEVAULT_TEST_DB_URL").unwrap_or_else(|_| {
            "postgres://simplevault:simplevault@127.0.0.1:55432/simplevault_test".to_string()
        });
        let targets = crate::db_query::parse_connection_targets(&connection_string).unwrap();
        let (allowed_host, allowed_port) = targets.first().cloned().unwrap();
        let config_json = format!(
            r#"{{
            "api_keys": [{{ "value": "db-query-key", "keys": "all", "operations": ["encrypt", "db_query"] }}],
            "server_port": 8080,
            "keys": {{
                "vault": {{ "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }}
            }},
            "db_destinations": {{
                "vault": [{{ "host": "{}", "port": {} }}]
            }}
        }}"#,
            allowed_host, allowed_port
        );
        let config: Config = serde_json::from_str(&config_json).unwrap();
        let app = build_router(config);

        let encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                json!({ "plaintext": connection_string }).to_string(),
            ))
            .unwrap();
        let encrypt_resp = app.clone().oneshot(encrypt_req).await.unwrap();
        assert_eq!(encrypt_resp.status(), StatusCode::OK);
        let encrypt_body = read_body(encrypt_resp).await;
        let encrypt_json: serde_json::Value = serde_json::from_slice(&encrypt_body).unwrap();
        let ciphertext = encrypt_json["ciphertext"].as_str().unwrap().to_string();

        let query_req = Request::post("/v1/vault/db-query")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "query": {
                        "sql": "select $1::int as n, $2::text as t",
                        "params": [
                            { "type": "int4", "value": 7 },
                            { "type": "text", "value": "ok" }
                        ]
                    },
                    "options": {
                        "timeout_ms": 3000,
                        "max_rows": 100
                    }
                })
                .to_string(),
            ))
            .unwrap();
        let query_resp = app.oneshot(query_req).await.unwrap();
        let query_status = query_resp.status();
        let query_body = read_body(query_resp).await;
        assert_eq!(
            query_status,
            StatusCode::OK,
            "db-query should succeed against test postgres; body={}",
            String::from_utf8_lossy(&query_body)
        );
        let query_json: serde_json::Value = serde_json::from_slice(&query_body).unwrap();
        assert_eq!(query_json["row_count"].as_u64().unwrap(), 1);
        assert_eq!(query_json["rows"][0][0].as_i64().unwrap(), 7);
        assert_eq!(query_json["rows"][0][1].as_str().unwrap(), "ok");
    }

    #[tokio::test]
    async fn db_query_reports_descriptive_sql_errors_when_enabled() {
        if std::env::var("SIMPLEVAULT_ENABLE_DB_TESTS").unwrap_or_default() != "1" {
            return;
        }
        let connection_string = std::env::var("SIMPLEVAULT_TEST_DB_URL").unwrap_or_else(|_| {
            "postgres://simplevault:simplevault@127.0.0.1:55432/simplevault_test".to_string()
        });
        let targets = crate::db_query::parse_connection_targets(&connection_string).unwrap();
        let (allowed_host, allowed_port) = targets.first().cloned().unwrap();
        let config_json = format!(
            r#"{{
            "api_keys": [{{ "value": "db-query-key", "keys": "all", "operations": ["encrypt", "db_query"] }}],
            "server_port": 8080,
            "keys": {{
                "vault": {{ "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }}
            }},
            "db_destinations": {{
                "vault": [{{ "host": "{}", "port": {} }}]
            }}
        }}"#,
            allowed_host, allowed_port
        );
        let config: Config = serde_json::from_str(&config_json).unwrap();
        let app = build_router(config);

        let encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                json!({ "plaintext": connection_string }).to_string(),
            ))
            .unwrap();
        let encrypt_resp = app.clone().oneshot(encrypt_req).await.unwrap();
        assert_eq!(encrypt_resp.status(), StatusCode::OK);
        let encrypt_body = read_body(encrypt_resp).await;
        let encrypt_json: serde_json::Value = serde_json::from_slice(&encrypt_body).unwrap();
        let ciphertext = encrypt_json["ciphertext"].as_str().unwrap().to_string();

        let query_req = Request::post("/v1/vault/db-query")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "query": {
                        "sql": "select missing_column from (select 1 as n) t"
                    },
                    "options": {
                        "timeout_ms": 3000,
                        "max_rows": 100
                    }
                })
                .to_string(),
            ))
            .unwrap();
        let query_resp = app.oneshot(query_req).await.unwrap();
        assert_eq!(query_resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let query_body = read_body(query_resp).await;
        let query_json: serde_json::Value = serde_json::from_slice(&query_body).unwrap();
        let error_message = query_json["error"].as_str().unwrap_or_default();
        assert!(
            error_message.contains("database error ["),
            "expected SQLSTATE/code in error message, got: {}",
            error_message
        );
        assert!(
            error_message
                .to_ascii_lowercase()
                .contains("missing_column")
                || error_message.to_ascii_lowercase().contains("column"),
            "expected column context in error message, got: {}",
            error_message
        );
    }

    #[tokio::test]
    async fn db_query_supports_typed_jsonb_params_when_enabled() {
        if std::env::var("SIMPLEVAULT_ENABLE_DB_TESTS").unwrap_or_default() != "1" {
            return;
        }
        let connection_string = std::env::var("SIMPLEVAULT_TEST_DB_URL").unwrap_or_else(|_| {
            "postgres://simplevault:simplevault@127.0.0.1:55432/simplevault_test".to_string()
        });
        let targets = crate::db_query::parse_connection_targets(&connection_string).unwrap();
        let (allowed_host, allowed_port) = targets.first().cloned().unwrap();
        let config_json = format!(
            r#"{{
            "api_keys": [{{ "value": "db-query-key", "keys": "all", "operations": ["encrypt", "db_query"] }}],
            "server_port": 8080,
            "keys": {{
                "vault": {{ "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }}
            }},
            "db_destinations": {{
                "vault": [{{ "host": "{}", "port": {} }}]
            }}
        }}"#,
            allowed_host, allowed_port
        );
        let config: Config = serde_json::from_str(&config_json).unwrap();
        let app = build_router(config);

        let encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                json!({ "plaintext": connection_string }).to_string(),
            ))
            .unwrap();
        let encrypt_resp = app.clone().oneshot(encrypt_req).await.unwrap();
        assert_eq!(encrypt_resp.status(), StatusCode::OK);
        let encrypt_body = read_body(encrypt_resp).await;
        let encrypt_json: serde_json::Value = serde_json::from_slice(&encrypt_body).unwrap();
        let ciphertext = encrypt_json["ciphertext"].as_str().unwrap().to_string();

        let query_req = Request::post("/v1/vault/db-query")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "query": {
                        "sql": "select $1::jsonb->>'kind' as kind, $2::varchar as label",
                        "params": [
                            { "type": "jsonb", "value": { "kind": "customer" } },
                            { "type": "varchar", "value": "gold" }
                        ]
                    }
                })
                .to_string(),
            ))
            .unwrap();
        let query_resp = app.oneshot(query_req).await.unwrap();
        assert_eq!(query_resp.status(), StatusCode::OK);
        let query_body = read_body(query_resp).await;
        let query_json: serde_json::Value = serde_json::from_slice(&query_body).unwrap();
        assert_eq!(query_json["row_count"].as_u64().unwrap(), 1);
        assert_eq!(query_json["rows"][0][0].as_str().unwrap(), "customer");
        assert_eq!(query_json["rows"][0][1].as_str().unwrap(), "gold");
    }

    #[tokio::test]
    async fn db_query_supports_typed_timestamptz_params_when_enabled() {
        if std::env::var("SIMPLEVAULT_ENABLE_DB_TESTS").unwrap_or_default() != "1" {
            return;
        }
        let connection_string = std::env::var("SIMPLEVAULT_TEST_DB_URL").unwrap_or_else(|_| {
            "postgres://simplevault:simplevault@127.0.0.1:55432/simplevault_test".to_string()
        });
        let targets = crate::db_query::parse_connection_targets(&connection_string).unwrap();
        let (allowed_host, allowed_port) = targets.first().cloned().unwrap();
        let config_json = format!(
            r#"{{
            "api_keys": [{{ "value": "db-query-key", "keys": "all", "operations": ["encrypt", "db_query"] }}],
            "server_port": 8080,
            "keys": {{
                "vault": {{ "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }}
            }},
            "db_destinations": {{
                "vault": [{{ "host": "{}", "port": {} }}]
            }}
        }}"#,
            allowed_host, allowed_port
        );
        let config: Config = serde_json::from_str(&config_json).unwrap();
        let app = build_router(config);

        let encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                json!({ "plaintext": connection_string }).to_string(),
            ))
            .unwrap();
        let encrypt_resp = app.clone().oneshot(encrypt_req).await.unwrap();
        assert_eq!(encrypt_resp.status(), StatusCode::OK);
        let encrypt_body = read_body(encrypt_resp).await;
        let encrypt_json: serde_json::Value = serde_json::from_slice(&encrypt_body).unwrap();
        let ciphertext = encrypt_json["ciphertext"].as_str().unwrap().to_string();

        let query_req = Request::post("/v1/vault/db-query")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "query": {
                        "sql": "select ($1::timestamptz at time zone 'UTC')::text as ts",
                        "params": [
                            { "type": "timestamptz", "value": "2025-01-02T03:04:05+00:00" }
                        ]
                    }
                })
                .to_string(),
            ))
            .unwrap();
        let query_resp = app.oneshot(query_req).await.unwrap();
        assert_eq!(query_resp.status(), StatusCode::OK);
        let query_body = read_body(query_resp).await;
        let query_json: serde_json::Value = serde_json::from_slice(&query_body).unwrap();
        assert_eq!(query_json["row_count"].as_u64().unwrap(), 1);
        assert!(
            query_json["rows"][0][0]
                .as_str()
                .unwrap_or_default()
                .starts_with("2025-01-02 03:04:05")
        );
    }

    #[tokio::test]
    async fn db_query_supports_typed_json_object_and_array_params_when_enabled() {
        if std::env::var("SIMPLEVAULT_ENABLE_DB_TESTS").unwrap_or_default() != "1" {
            return;
        }
        let connection_string = std::env::var("SIMPLEVAULT_TEST_DB_URL").unwrap_or_else(|_| {
            "postgres://simplevault:simplevault@127.0.0.1:55432/simplevault_test".to_string()
        });
        let targets = crate::db_query::parse_connection_targets(&connection_string).unwrap();
        let (allowed_host, allowed_port) = targets.first().cloned().unwrap();
        let config_json = format!(
            r#"{{
            "api_keys": [{{ "value": "db-query-key", "keys": "all", "operations": ["encrypt", "db_query"] }}],
            "server_port": 8080,
            "keys": {{
                "vault": {{ "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }}
            }},
            "db_destinations": {{
                "vault": [{{ "host": "{}", "port": {} }}]
            }}
        }}"#,
            allowed_host, allowed_port
        );
        let config: Config = serde_json::from_str(&config_json).unwrap();
        let app = build_router(config);

        let encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                json!({ "plaintext": connection_string }).to_string(),
            ))
            .unwrap();
        let encrypt_resp = app.clone().oneshot(encrypt_req).await.unwrap();
        assert_eq!(encrypt_resp.status(), StatusCode::OK);
        let encrypt_body = read_body(encrypt_resp).await;
        let encrypt_json: serde_json::Value = serde_json::from_slice(&encrypt_body).unwrap();
        let ciphertext = encrypt_json["ciphertext"].as_str().unwrap().to_string();

        let query_req = Request::post("/v1/vault/db-query")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "query": {
                        "sql": "select $1::jsonb->>'kind' as kind, jsonb_array_length($2::jsonb) as n",
                        "params": [
                            { "type": "jsonb", "value": { "kind": "customer" } },
                            { "type": "jsonb", "value": [1, 2, 3] }
                        ]
                    }
                })
                .to_string(),
            ))
            .unwrap();
        let query_resp = app.oneshot(query_req).await.unwrap();
        assert_eq!(query_resp.status(), StatusCode::OK);
        let query_body = read_body(query_resp).await;
        let query_json: serde_json::Value = serde_json::from_slice(&query_body).unwrap();
        assert_eq!(query_json["row_count"].as_u64().unwrap(), 1);
        assert_eq!(query_json["rows"][0][0].as_str().unwrap(), "customer");
        assert_eq!(query_json["rows"][0][1].as_i64().unwrap(), 3);
    }

    #[tokio::test]
    async fn db_query_preserves_select_column_order_when_enabled() {
        if std::env::var("SIMPLEVAULT_ENABLE_DB_TESTS").unwrap_or_default() != "1" {
            return;
        }
        let connection_string = std::env::var("SIMPLEVAULT_TEST_DB_URL").unwrap_or_else(|_| {
            "postgres://simplevault:simplevault@127.0.0.1:55432/simplevault_test".to_string()
        });
        let targets = crate::db_query::parse_connection_targets(&connection_string).unwrap();
        let (allowed_host, allowed_port) = targets.first().cloned().unwrap();
        let config_json = format!(
            r#"{{
            "api_keys": [{{ "value": "db-query-key", "keys": "all", "operations": ["encrypt", "db_query"] }}],
            "server_port": 8080,
            "keys": {{
                "vault": {{ "1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }}
            }},
            "db_destinations": {{
                "vault": [{{ "host": "{}", "port": {} }}]
            }}
        }}"#,
            allowed_host, allowed_port
        );
        let config: Config = serde_json::from_str(&config_json).unwrap();
        let app = build_router(config);

        let encrypt_req = Request::post("/v1/vault/encrypt")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                json!({ "plaintext": connection_string }).to_string(),
            ))
            .unwrap();
        let encrypt_resp = app.clone().oneshot(encrypt_req).await.unwrap();
        assert_eq!(encrypt_resp.status(), StatusCode::OK);
        let encrypt_body = read_body(encrypt_resp).await;
        let encrypt_json: serde_json::Value = serde_json::from_slice(&encrypt_body).unwrap();
        let ciphertext = encrypt_json["ciphertext"].as_str().unwrap().to_string();

        let query_req = Request::post("/v1/vault/db-query")
            .header("content-type", "application/json")
            .header("x-api-key", "db-query-key")
            .body(Body::from(
                json!({
                    "ciphertext": ciphertext,
                    "query": {
                        "sql": "select 1 as z, 2 as a, 3 as m"
                    }
                })
                .to_string(),
            ))
            .unwrap();
        let query_resp = app.oneshot(query_req).await.unwrap();
        assert_eq!(query_resp.status(), StatusCode::OK);
        let query_body = read_body(query_resp).await;
        let query_json: serde_json::Value = serde_json::from_slice(&query_body).unwrap();
        assert_eq!(query_json["columns"][0]["name"].as_str().unwrap(), "z");
        assert_eq!(query_json["columns"][1]["name"].as_str().unwrap(), "a");
        assert_eq!(query_json["columns"][2]["name"].as_str().unwrap(), "m");
        assert_eq!(query_json["rows"][0][0].as_i64().unwrap(), 1);
        assert_eq!(query_json["rows"][0][1].as_i64().unwrap(), 2);
        assert_eq!(query_json["rows"][0][2].as_i64().unwrap(), 3);
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
