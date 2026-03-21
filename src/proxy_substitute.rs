use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const DEFAULT_PLACEHOLDER: &str = "{{SIMPLEVAULT_PLAINTEXT}}";

#[derive(Debug, Deserialize)]
pub struct ProxySubstituteRequest {
    pub ciphertext: crate::crypto::CipherText,
    pub request: OutboundRequest,
    #[serde(default)]
    pub placeholder: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OutboundRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProxySubstituteResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

pub struct PreparedOutboundRequest {
    pub method: Method,
    pub url: Url,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

pub fn prepare_outbound_request(
    request: OutboundRequest,
    plaintext: &str,
    request_placeholder: Option<&str>,
) -> Result<PreparedOutboundRequest, String> {
    let placeholder = request_placeholder
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .unwrap_or(DEFAULT_PLACEHOLDER);

    let method: Method = request
        .method
        .parse()
        .map_err(|_| format!("invalid outbound method: {}", request.method))?;
    let substituted_url = request.url.replace(placeholder, plaintext);
    let url = Url::parse(&substituted_url)
        .map_err(|e| format!("invalid outbound URL after substitution: {}", e))?;

    let mut substituted_headers: HashMap<String, String> = HashMap::new();
    for (name, value) in request.headers.unwrap_or_default() {
        if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        substituted_headers.insert(name, value.replace(placeholder, plaintext));
    }

    let substituted_body = request.body.map(|b| b.replace(placeholder, plaintext));

    Ok(PreparedOutboundRequest {
        method,
        url,
        headers: substituted_headers,
        body: substituted_body,
    })
}

pub async fn execute_outbound_request(
    client: &Client,
    outbound: PreparedOutboundRequest,
) -> Result<ProxySubstituteResponse, anyhow::Error> {
    let mut request_builder = client.request(outbound.method, outbound.url);

    let mut header_map = HeaderMap::new();
    for (name, value) in outbound.headers {
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid outbound header name: {}", name))?;
        let header_value = HeaderValue::from_str(&value).map_err(|_| {
            anyhow::anyhow!("invalid outbound header value for {}: {}", name, value)
        })?;
        header_map.insert(header_name, header_value);
    }
    request_builder = request_builder.headers(header_map);

    if let Some(body) = outbound.body {
        request_builder = request_builder.body(body);
    }

    let upstream_response = request_builder.send().await?;
    let status = upstream_response.status().as_u16();
    let mut response_headers = HashMap::new();
    for (name, value) in upstream_response.headers() {
        if name.as_str().eq_ignore_ascii_case("content-length")
            || name.as_str().eq_ignore_ascii_case("transfer-encoding")
            || name.as_str().eq_ignore_ascii_case("connection")
            || name.as_str().eq_ignore_ascii_case("host")
        {
            continue;
        }
        if let Ok(as_str) = value.to_str() {
            response_headers.insert(name.to_string(), as_str.to_string());
        }
    }

    let body = upstream_response.text().await?;
    Ok(ProxySubstituteResponse {
        status,
        headers: response_headers,
        body,
    })
}

pub fn is_https_or_localhost(url: &Url) -> bool {
    if url.scheme() == "https" {
        return true;
    }
    if url.scheme() != "http" {
        return false;
    }
    matches!(url.host_str(), Some("localhost") | Some("127.0.0.1"))
}

pub fn validate_destination_safety(url: &Url) -> Result<(), (StatusCode, String)> {
    if !is_https_or_localhost(url) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "outbound url must use https (http allowed only for localhost)".to_string(),
        ));
    }
    Ok(())
}
