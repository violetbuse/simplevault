use simplevault::api;
use simplevault::client::{
    ClientError, CreateSignatureRequest, DbQueryPayload, DbQueryRequest, HttpTransport,
    InMemoryTransport, ProxySubstituteRequest, SimpleVaultClient, VerifySignatureRequest,
};
use simplevault::config::Config;
use simplevault::proxy_substitute::OutboundRequest;

fn test_config() -> Config {
    serde_json::from_str(
        r#"{
            "api_keys": [{ "value": "test-key", "keys": "all", "operations": ["encrypt", "decrypt", "rotate", "verify", "sign"] }],
            "server_port": 8080,
            "keys": {
                "vault": {
                    "1": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "2": "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
                }
            }
        }"#,
    )
    .expect("test config should deserialize")
}

fn clone_ciphertext(
    ciphertext: &simplevault::crypto::CipherText,
) -> simplevault::crypto::CipherText {
    serde_json::from_value(serde_json::to_value(ciphertext).expect("serialize ciphertext"))
        .expect("deserialize ciphertext")
}

async fn run_contract(client: &SimpleVaultClient) {
    let encrypted = client
        .encrypt("integration test secret")
        .await
        .expect("encrypt should succeed");

    let decrypted = client
        .decrypt(clone_ciphertext(&encrypted.ciphertext))
        .await
        .expect("decrypt should succeed");
    assert_eq!(decrypted.plaintext, "integration test secret");

    let version = client.version().await.expect("version should succeed");
    assert!(version.version >= 1);

    let rotated = client
        .rotate(clone_ciphertext(&encrypted.ciphertext))
        .await
        .expect("rotate should succeed");
    let roundtrip = client
        .decrypt(rotated.ciphertext)
        .await
        .expect("decrypt rotated should succeed");
    assert_eq!(roundtrip.plaintext, "integration test secret");

    let secret = client
        .encrypt("whsec_integration_secret")
        .await
        .expect("encrypt signature secret should succeed");
    let payload_hex = hex::encode(br#"{"id":"evt_integration"}"#);
    let create_signature_response = client
        .create_signature(CreateSignatureRequest {
            ciphertext: clone_ciphertext(&secret.ciphertext),
            payload: payload_hex.clone(),
            algorithm: "hmac-sha256".to_string(),
        })
        .await
        .expect("create signature should succeed");
    let verify = client
        .verify_signature(VerifySignatureRequest {
            ciphertext: clone_ciphertext(&secret.ciphertext),
            payload: payload_hex,
            signature: create_signature_response.signature,
            algorithm: "hmac-sha256".to_string(),
        })
        .await
        .expect("verify signature should succeed");
    assert!(verify.verified);

    let proxy_error = client
        .proxy_substitute(ProxySubstituteRequest {
            ciphertext: clone_ciphertext(&secret.ciphertext),
            request: OutboundRequest {
                method: "GET".to_string(),
                url: "https://example.com".to_string(),
                headers: None,
                body: None,
            },
            placeholder: None,
        })
        .await
        .expect_err("proxy should be forbidden for this API key");
    match proxy_error {
        ClientError::HttpStatus { status, .. } => assert_eq!(status, 403),
        _ => panic!("expected http status error for proxy"),
    }

    let db_error = client
        .db_query(DbQueryRequest {
            ciphertext: clone_ciphertext(&secret.ciphertext),
            query: DbQueryPayload {
                sql: "select 1".to_string(),
                params: None,
            },
            options: None,
        })
        .await
        .expect_err("db query should be forbidden for this API key");
    match db_error {
        ClientError::HttpStatus { status, .. } => assert_eq!(status, 403),
        _ => panic!("expected http status error for db_query"),
    }
}

#[tokio::test]
async fn in_memory_transport_contract() {
    let app = api::build_router(test_config());
    let transport = InMemoryTransport::new(app, "vault", Some("test-key".to_string()));
    let client = SimpleVaultClient::new(transport);
    run_contract(&client).await;
}

#[tokio::test]
async fn http_transport_contract() {
    let app = api::build_router(test_config());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let transport = HttpTransport::new(
        format!("http://{}", addr),
        "vault",
        Some("test-key".to_string()),
    );
    let client = SimpleVaultClient::new(transport);
    run_contract(&client).await;

    server.abort();
}
