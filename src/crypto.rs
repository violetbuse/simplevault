use std::fmt::Debug;

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadCore, KeyInit},
};
use hmac::{Hmac, Mac};
use secrets::{SecretBox, SecretVec};
use serde::de::{Deserializer, Error as SerdeError, Visitor};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

// AES-GCM-256 encryption key
pub struct EncryptionKey {
    // key: [u8; 32],
    key: SecretBox<[u8; 32]>,
}

impl Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionKey")
            .field("key", &"********")
            .finish()
    }
}

impl<'de> serde::Deserialize<'de> for EncryptionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HexKeyVisitor;

        impl<'de> Visitor<'de> for HexKeyVisitor {
            type Value = EncryptionKey;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "a hex-encoded string of exactly 64 characters representing 32 bytes"
                )
            }

            fn visit_str<E>(self, v: &str) -> Result<EncryptionKey, E>
            where
                E: SerdeError,
            {
                if v.len() != 64 {
                    return Err(E::invalid_length(
                        v.len(),
                        &"hex string must be exactly 64 characters (32 bytes)",
                    ));
                }

                let bytes = hex::decode(v).map_err(|e| E::custom(format!("invalid hex: {}", e)))?;

                if bytes.len() != 32 {
                    return Err(E::invalid_length(
                        bytes.len(),
                        &"dehexed bytes must be exactly 32 bytes for AES-256",
                    ));
                }

                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);

                Ok(EncryptionKey {
                    key: SecretBox::new(|s| *s = key),
                })
            }
        }

        deserializer.deserialize_str(HexKeyVisitor)
    }
}

// this will be represented as a hex encoded string
// key_version | ciphertext | nonce
// vx:<hex_ciphertext>:<hex_nonce>
pub struct CipherText {
    pub key_version: u32,
    // 96 bit nonce
    nonce: SecretBox<[u8; 12]>,
    ciphertext: SecretVec<u8>,
}

impl CipherText {
    pub fn decrypt(&self, key: &EncryptionKey) -> Result<SecretVec<u8>, anyhow::Error> {
        let cipher = Aes256Gcm::new_from_slice(key.key.borrow().as_slice())
            .map_err(|e| anyhow::anyhow!("invalid key: {}", e))?;
        let nonce_bytes = *self.nonce.borrow();
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, self.ciphertext.borrow().as_ref())
            .map_err(|e| anyhow::anyhow!("decryption failed: {}", e))?;
        Ok(SecretVec::new(plaintext.len(), |buf| {
            buf.copy_from_slice(&plaintext);
        }))
    }

    pub fn encrypt(
        plaintext: SecretVec<u8>,
        key: &EncryptionKey,
        key_version: u32,
    ) -> Result<CipherText, anyhow::Error> {
        let cipher = Aes256Gcm::new_from_slice(key.key.borrow().as_slice())
            .map_err(|e| anyhow::anyhow!("invalid key: {}", e))?;
        let nonce = Aes256Gcm::generate_nonce(&mut rand_core::OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.borrow().as_ref())
            .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;
        let nonce_arr: [u8; 12] = nonce
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("nonce length mismatch"))?;
        let ct_len = ciphertext.len();
        let ciphertext_secret = SecretVec::new(ct_len, |buf| buf.copy_from_slice(&ciphertext));
        Ok(CipherText {
            key_version,
            nonce: SecretBox::new(|s| *s = nonce_arr),
            ciphertext: ciphertext_secret,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureAlgorithm {
    HmacSha1,
    HmacSha256,
    HmacSha512,
}

impl SignatureAlgorithm {
    fn parse(input: &str) -> Result<Self, anyhow::Error> {
        let normalized = input
            .trim()
            .to_ascii_lowercase()
            .replace('_', "-")
            .replace(' ', "");
        match normalized.as_str() {
            "hmac-sha1" | "sha1" => Ok(SignatureAlgorithm::HmacSha1),
            "hmac-sha256" | "sha256" => Ok(SignatureAlgorithm::HmacSha256),
            "hmac-sha512" | "sha512" => Ok(SignatureAlgorithm::HmacSha512),
            _ => Err(anyhow::anyhow!("unsupported signature algorithm: {}", input)),
        }
    }
}

fn decode_hex_input(name: &str, value: &str) -> Result<Vec<u8>, anyhow::Error> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(anyhow::anyhow!("{} cannot be empty", name));
    }
    if trimmed.len() % 2 != 0 {
        return Err(anyhow::anyhow!("{} must be hex with even length", name));
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!("{} must be hex-encoded", name));
    }
    hex::decode(trimmed).map_err(|e| anyhow::anyhow!("invalid {} hex: {}", name, e))
}

fn verify_hmac_sha1(secret: &[u8], payload: &[u8], provided_signature: &[u8]) -> Result<bool, anyhow::Error> {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret)
        .map_err(|e| anyhow::anyhow!("invalid HMAC key: {}", e))?;
    mac.update(payload);
    Ok(mac.verify_slice(provided_signature).is_ok())
}

fn verify_hmac_sha256(
    secret: &[u8],
    payload: &[u8],
    provided_signature: &[u8],
) -> Result<bool, anyhow::Error> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
        .map_err(|e| anyhow::anyhow!("invalid HMAC key: {}", e))?;
    mac.update(payload);
    Ok(mac.verify_slice(provided_signature).is_ok())
}

fn verify_hmac_sha512(
    secret: &[u8],
    payload: &[u8],
    provided_signature: &[u8],
) -> Result<bool, anyhow::Error> {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(secret)
        .map_err(|e| anyhow::anyhow!("invalid HMAC key: {}", e))?;
    mac.update(payload);
    Ok(mac.verify_slice(provided_signature).is_ok())
}

pub fn verify_signature_with_encrypted_secret(
    encrypted_secret: &CipherText,
    key: &EncryptionKey,
    payload: &[u8],
    signature: &str,
    algorithm: &str,
) -> Result<bool, anyhow::Error> {
    let signature_bytes = decode_hex_input("signature", signature)?;
    verify_signature_with_encrypted_secret_bytes(
        encrypted_secret,
        key,
        payload,
        &signature_bytes,
        algorithm,
    )
}

pub fn verify_signature_with_encrypted_secret_bytes(
    encrypted_secret: &CipherText,
    key: &EncryptionKey,
    payload: &[u8],
    signature: &[u8],
    algorithm: &str,
) -> Result<bool, anyhow::Error> {
    let secret = encrypted_secret.decrypt(key)?;
    let parsed_algorithm = SignatureAlgorithm::parse(algorithm)?;

    match parsed_algorithm {
        SignatureAlgorithm::HmacSha1 => {
            verify_hmac_sha1(secret.borrow().as_ref(), payload, signature)
        }
        SignatureAlgorithm::HmacSha256 => {
            verify_hmac_sha256(secret.borrow().as_ref(), payload, signature)
        }
        SignatureAlgorithm::HmacSha512 => {
            verify_hmac_sha512(secret.borrow().as_ref(), payload, signature)
        }
    }
}

impl Debug for CipherText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CipherText")
            .field("key_version", &self.key_version)
            .field("nonce", &"********")
            .field("ciphertext", &"********")
            .finish()
    }
}

impl Serialize for CipherText {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let nonce_hex = hex::encode(*self.nonce.borrow());
        let ct_hex = hex::encode(&*self.ciphertext.borrow());
        let s = format!("v{}:{}:{}", self.key_version, ct_hex, nonce_hex);
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for CipherText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CipherTextVisitor;

        impl<'de> Visitor<'de> for CipherTextVisitor {
            type Value = CipherText;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "a string in format v<key_version>:<hex_ciphertext>:<hex_nonce>"
                )
            }

            fn visit_str<E>(self, v: &str) -> Result<CipherText, E>
            where
                E: SerdeError,
            {
                let parts: Vec<&str> = v.splitn(3, ':').collect();
                if parts.len() != 3 {
                    return Err(E::custom(format!(
                        "expected v<key_version>:<hex_ciphertext>:<hex_nonce>, got {} parts",
                        parts.len()
                    )));
                }

                let key_version = parts[0]
                    .strip_prefix('v')
                    .ok_or_else(|| E::custom("first part must start with 'v'"))?
                    .parse::<u32>()
                    .map_err(|e| E::custom(format!("invalid key_version: {}", e)))?;

                let ct_bytes = hex::decode(parts[1])
                    .map_err(|e| E::custom(format!("invalid ciphertext hex: {}", e)))?;

                let nonce_bytes = hex::decode(parts[2])
                    .map_err(|e| E::custom(format!("invalid nonce hex: {}", e)))?;

                if nonce_bytes.len() != 12 {
                    return Err(E::invalid_length(
                        nonce_bytes.len(),
                        &"nonce must be exactly 12 bytes (96 bits)",
                    ));
                }

                let mut nonce_arr = [0u8; 12];
                nonce_arr.copy_from_slice(&nonce_bytes);

                let ct_len = ct_bytes.len();
                let ciphertext = SecretVec::new(ct_len, |buf| buf.copy_from_slice(&ct_bytes));

                Ok(CipherText {
                    key_version,
                    nonce: SecretBox::new(|s| *s = nonce_arr),
                    ciphertext,
                })
            }
        }

        deserializer.deserialize_str(CipherTextVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use secrets::SecretVec;
    use sha2::Sha256;

    fn make_key_hex() -> &'static str {
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }

    fn make_encryption_key() -> EncryptionKey {
        let json = format!(r#""{}""#, make_key_hex());
        serde_json::from_str(&json).unwrap()
    }

    fn make_plaintext(s: &str) -> SecretVec<u8> {
        let bytes = s.as_bytes();
        SecretVec::new(bytes.len(), |buf| buf.copy_from_slice(bytes))
    }

    // --- EncryptionKey tests ---

    #[test]
    fn encryption_key_deserialize_valid_hex() {
        let json = format!(r#""{}""#, make_key_hex());
        let key: EncryptionKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key.key.borrow().as_slice().len(), 32);
    }

    #[test]
    fn encryption_key_deserialize_rejects_too_short() {
        let json = r#""0123456789abcdef""#;
        let result: Result<EncryptionKey, _> = serde_json::from_str(json);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("64") || err.to_string().contains("length"));
    }

    #[test]
    fn encryption_key_deserialize_rejects_too_long() {
        let json = r#""0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef""#;
        let result: Result<EncryptionKey, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn encryption_key_deserialize_rejects_invalid_hex() {
        let json = r#""zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz""#;
        let result: Result<EncryptionKey, _> = serde_json::from_str(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().to_lowercase().contains("hex"));
    }

    #[test]
    fn encryption_key_deserialize_rejects_odd_length_hex() {
        let json = r#""0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0""#;
        let result: Result<EncryptionKey, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn encryption_key_debug_redacts_key() {
        let key = make_encryption_key();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("EncryptionKey"));
        assert!(debug_str.contains("********"));
        assert!(!debug_str.contains("01234567"));
    }

    // --- CipherText encrypt/decrypt tests ---

    #[test]
    fn ciphertext_encrypt_decrypt_roundtrip() {
        let key = make_encryption_key();
        let plaintext = make_plaintext("hello world");
        let ct = CipherText::encrypt(plaintext, &key, 1).unwrap();
        let decrypted = ct.decrypt(&key).unwrap();
        assert_eq!(decrypted.borrow().as_ref(), b"hello world");
    }

    #[test]
    fn ciphertext_encrypt_decrypt_empty_plaintext() {
        let key = make_encryption_key();
        let plaintext = make_plaintext("");
        let ct = CipherText::encrypt(plaintext, &key, 1).unwrap();
        let decrypted = ct.decrypt(&key).unwrap();
        assert_eq!(decrypted.borrow().as_ref(), b"");
    }

    #[test]
    fn ciphertext_encrypt_decrypt_large_plaintext() {
        let key = make_encryption_key();
        let data = "x".repeat(100_000);
        let plaintext = make_plaintext(&data);
        let ct = CipherText::encrypt(plaintext, &key, 1).unwrap();
        let decrypted = ct.decrypt(&key).unwrap();
        assert_eq!(decrypted.borrow().as_ref(), data.as_bytes());
    }

    #[test]
    fn ciphertext_encrypt_decrypt_binary_data() {
        let key = make_encryption_key();
        let bytes: Vec<u8> = (0u8..=255).collect();
        let plaintext = SecretVec::new(bytes.len(), |buf| buf.copy_from_slice(&bytes));
        let ct = CipherText::encrypt(plaintext, &key, 1).unwrap();
        let decrypted = ct.decrypt(&key).unwrap();
        assert_eq!(decrypted.borrow().as_ref(), bytes.as_slice());
    }

    #[test]
    fn ciphertext_encrypt_preserves_key_version() {
        let key = make_encryption_key();
        let plaintext = make_plaintext("test");
        let ct = CipherText::encrypt(plaintext, &key, 42).unwrap();
        assert_eq!(ct.key_version, 42);
    }

    #[test]
    fn ciphertext_decrypt_with_wrong_key_fails() {
        let key1 = make_encryption_key();
        let key2_json = r#""fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210""#;
        let key2: EncryptionKey = serde_json::from_str(key2_json).unwrap();

        let plaintext = make_plaintext("secret");
        let ct = CipherText::encrypt(plaintext, &key1, 1).unwrap();
        let result = ct.decrypt(&key2);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().to_lowercase().contains("decrypt"));
    }

    #[test]
    fn ciphertext_different_plaintexts_produce_different_ciphertexts() {
        let key = make_encryption_key();
        let pt1 = make_plaintext("message one");
        let pt2 = make_plaintext("message two");
        let ct1 = CipherText::encrypt(pt1, &key, 1).unwrap();
        let ct2 = CipherText::encrypt(pt2, &key, 1).unwrap();
        let s1 = serde_json::to_string(&ct1).unwrap();
        let s2 = serde_json::to_string(&ct2).unwrap();
        assert_ne!(s1, s2, "different plaintexts should produce different ciphertexts");
    }

    #[test]
    fn ciphertext_same_plaintext_different_nonces() {
        let key = make_encryption_key();
        let pt1 = make_plaintext("same");
        let ct1 = CipherText::encrypt(pt1, &key, 1).unwrap();
        let pt2 = make_plaintext("same");
        let ct2 = CipherText::encrypt(pt2, &key, 1).unwrap();
        let s1 = serde_json::to_string(&ct1).unwrap();
        let s2 = serde_json::to_string(&ct2).unwrap();
        assert_ne!(s1, s2, "same plaintext should get different nonces each time");
    }

    // --- CipherText serialize/deserialize tests ---

    #[test]
    fn ciphertext_serialize_format() {
        let key = make_encryption_key();
        let plaintext = make_plaintext("test");
        let ct = CipherText::encrypt(plaintext, &key, 7).unwrap();
        let s = serde_json::to_string(&ct).unwrap();
        assert!(s.starts_with("\"v7:"));
        assert!(s.ends_with("\""));
        let inner = s.trim_matches('"');
        let parts: Vec<&str> = inner.splitn(3, ':').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "v7");
        assert!(parts[1].chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(parts[2].len(), 24, "nonce hex should be 12 bytes = 24 hex chars");
        assert!(parts[2].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn ciphertext_deserialize_valid() {
        let key = make_encryption_key();
        let plaintext = make_plaintext("roundtrip");
        let ct = CipherText::encrypt(plaintext, &key, 1).unwrap();
        let s = serde_json::to_string(&ct).unwrap();
        let ct2: CipherText = serde_json::from_str(&s).unwrap();
        assert_eq!(ct.key_version, ct2.key_version);
        let decrypted = ct2.decrypt(&key).unwrap();
        assert_eq!(decrypted.borrow().as_ref(), b"roundtrip");
    }

    #[test]
    fn ciphertext_serialize_deserialize_roundtrip() {
        let key = make_encryption_key();
        let plaintext = make_plaintext("serialize me");
        let ct = CipherText::encrypt(plaintext, &key, 99).unwrap();
        let json = serde_json::to_string(&ct).unwrap();
        let restored: CipherText = serde_json::from_str(&json).unwrap();
        assert_eq!(ct.key_version, restored.key_version);
        let orig_dec = ct.decrypt(&key).unwrap();
        let rest_dec = restored.decrypt(&key).unwrap();
        assert_eq!(orig_dec.borrow().as_ref(), rest_dec.borrow().as_ref());
    }

    #[test]
    fn ciphertext_deserialize_rejects_wrong_parts_count() {
        let json = r#""v1:abc123""#;
        let result: Result<CipherText, _> = serde_json::from_str(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("parts"));
    }

    #[test]
    fn ciphertext_deserialize_rejects_missing_v_prefix() {
        let json = r#""1:000000000000000000000000000000000000000000000000:000000000000000000000000""#;
        let result: Result<CipherText, _> = serde_json::from_str(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("v"));
    }

    #[test]
    fn ciphertext_deserialize_rejects_invalid_key_version() {
        let json = r#""vx:000000000000000000000000000000000000000000000000:000000000000000000000000""#;
        let result: Result<CipherText, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn ciphertext_deserialize_rejects_invalid_ciphertext_hex() {
        let json = r#""v1:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz:000000000000000000000000""#;
        let result: Result<CipherText, _> = serde_json::from_str(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().to_lowercase().contains("hex"));
    }

    #[test]
    fn ciphertext_deserialize_rejects_invalid_nonce_hex() {
        let json = r#""v1:000000000000000000000000000000000000000000000000:zzzzzzzzzzzzzzzzzzzzzzzz""#;
        let result: Result<CipherText, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn ciphertext_deserialize_rejects_wrong_nonce_length() {
        let json = r#""v1:000000000000000000000000000000000000000000000000:000000000000000000""#;
        let result: Result<CipherText, _> = serde_json::from_str(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("12"));
    }

    #[test]
    fn ciphertext_deserialize_rejects_nonce_too_long() {
        let json = r#""v1:000000000000000000000000000000000000000000000000:0000000000000000000000000000""#;
        let result: Result<CipherText, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // --- CipherText Debug tests ---

    #[test]
    fn ciphertext_debug_redacts_sensitive_data() {
        let key = make_encryption_key();
        let plaintext = make_plaintext("secret");
        let ct = CipherText::encrypt(plaintext, &key, 1).unwrap();
        let debug_str = format!("{:?}", ct);
        assert!(debug_str.contains("CipherText"));
        assert!(debug_str.contains("key_version"));
        assert!(debug_str.contains("********"));
        assert!(!debug_str.contains("secret"));
    }

    // --- Tampering tests ---

    #[test]
    fn ciphertext_tampered_ciphertext_decrypt_fails() {
        let key = make_encryption_key();
        let plaintext = make_plaintext("original");
        let ct = CipherText::encrypt(plaintext, &key, 1).unwrap();
        let json = serde_json::to_string(&ct).unwrap();
        let inner = json.trim_matches('"');
        let parts: Vec<&str> = inner.splitn(3, ':').collect();
        let mut ct_chars: Vec<char> = parts[1].chars().collect();
        if !ct_chars.is_empty() {
            ct_chars[0] = if ct_chars[0] == '0' { '1' } else { '0' };
        }
        let tampered_ct = ct_chars.into_iter().collect::<String>();
        let tampered = format!("\"{}:{}:{}\"", parts[0], tampered_ct, parts[2]);
        let ct_tampered: CipherText = serde_json::from_str(&tampered).unwrap();
        let result = ct_tampered.decrypt(&key);
        assert!(result.is_err());
    }

    #[test]
    fn ciphertext_tampered_nonce_decrypt_fails() {
        let key = make_encryption_key();
        let plaintext = make_plaintext("original");
        let ct = CipherText::encrypt(plaintext, &key, 1).unwrap();
        let s = serde_json::to_string(&ct).unwrap();
        let inner = s.trim_matches('"');
        let parts: Vec<&str> = inner.splitn(3, ':').collect();
        let tampered = format!(
            "\"{}:{}:ffffffffffffffffffffffff\"",
            parts[0],
            parts[1]
        );
        let ct_tampered: CipherText = serde_json::from_str(&tampered).unwrap();
        let result = ct_tampered.decrypt(&key);
        assert!(result.is_err());
    }

    #[test]
    fn verify_signature_with_encrypted_secret_accepts_hmac_sha256_hex() {
        let key = make_encryption_key();
        let secret = make_plaintext("whsec_test_secret");
        let encrypted_secret = CipherText::encrypt(secret, &key, 1).unwrap();
        let payload = b"{\"id\":\"evt_test\"}";

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"whsec_test_secret").unwrap();
        mac.update(payload);
        let expected = mac.finalize().into_bytes();
        let signature = hex::encode(expected);

        let verified = verify_signature_with_encrypted_secret(
            &encrypted_secret,
            &key,
            payload,
            &signature,
            "hmac-sha256",
        )
        .unwrap();

        assert!(verified);
    }

    #[test]
    fn verify_signature_with_encrypted_secret_rejects_mismatch() {
        let key = make_encryption_key();
        let secret = make_plaintext("whsec_test_secret");
        let encrypted_secret = CipherText::encrypt(secret, &key, 1).unwrap();
        let payload = b"payload";

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"wrong_secret").unwrap();
        mac.update(payload);
        let expected = mac.finalize().into_bytes();
        let signature = hex::encode(expected);

        let verified = verify_signature_with_encrypted_secret(
            &encrypted_secret,
            &key,
            payload,
            &signature,
            "sha256",
        )
        .unwrap();

        assert!(!verified);
    }

    #[test]
    fn verify_signature_with_encrypted_secret_rejects_unknown_algorithm() {
        let key = make_encryption_key();
        let secret = make_plaintext("whsec_test_secret");
        let encrypted_secret = CipherText::encrypt(secret, &key, 1).unwrap();

        let result = verify_signature_with_encrypted_secret(
            &encrypted_secret,
            &key,
            b"payload",
            "abcd",
            "rsa-sha256",
        );

        assert!(result.is_err());
    }

    #[test]
    fn verify_signature_with_encrypted_secret_rejects_non_hex_signature() {
        let key = make_encryption_key();
        let secret = make_plaintext("whsec_test_secret");
        let encrypted_secret = CipherText::encrypt(secret, &key, 1).unwrap();

        let result = verify_signature_with_encrypted_secret(
            &encrypted_secret,
            &key,
            b"payload",
            "base64-like+/",
            "hmac-sha256",
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hex"));
    }
}
