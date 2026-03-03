/**
 * AES-256-GCM crypto matching the SimpleVault Rust format.
 * Ciphertext format: v{version}:{hex_ciphertext}:{hex_nonce}
 * - ciphertext includes the 16-byte GCM auth tag appended
 * - nonce is 12 bytes (96 bits)
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const NONCE_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

export interface EncryptionKey {
  readonly bytes: Buffer;
}

export function parseKey(hexKey: string): EncryptionKey {
  if (hexKey.length !== 64 || !/^[0-9a-fA-F]+$/.test(hexKey)) {
    throw new Error('key must be exactly 64 hex characters (32 bytes)');
  }
  return { bytes: Buffer.from(hexKey, 'hex') };
}

export interface CipherText {
  keyVersion: number;
  ciphertext: string;
}

/**
 * Parse ciphertext string in format v{version}:{hex_ct}:{hex_nonce}
 */
export function parseCipherText(s: string): { keyVersion: number; nonce: Buffer; ciphertext: Buffer } {
  const parts = s.split(':');
  if (parts.length !== 3) {
    throw new Error(`expected v<key_version>:<hex_ciphertext>:<hex_nonce>, got ${parts.length} parts`);
  }
  const versionMatch = parts[0].match(/^v(.+)$/);
  if (!versionMatch) {
    throw new Error("first part must start with 'v'");
  }
  const keyVersion = parseInt(versionMatch[1], 10);
  if (isNaN(keyVersion) || keyVersion < 0) {
    throw new Error('invalid key_version');
  }
  const ctBytes = Buffer.from(parts[1], 'hex');
  const nonceBytes = Buffer.from(parts[2], 'hex');
  if (nonceBytes.length !== NONCE_LENGTH) {
    throw new Error('nonce must be exactly 12 bytes (96 bits)');
  }
  return { keyVersion, nonce: nonceBytes, ciphertext: ctBytes };
}

/**
 * Encrypt plaintext with AES-256-GCM. Returns ciphertext in v{version}:{hex}:{hex} format.
 */
export function encrypt(
  plaintext: Buffer | string,
  key: EncryptionKey,
  keyVersion: number
): string {
  const plaintextBuf = typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : plaintext;
  const nonce = randomBytes(NONCE_LENGTH);

  const cipher = createCipheriv(ALGORITHM, key.bytes, nonce, { authTagLength: AUTH_TAG_LENGTH });
  const encrypted = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const ctWithTag = Buffer.concat([encrypted, authTag]);
  return `v${keyVersion}:${ctWithTag.toString('hex')}:${nonce.toString('hex')}`;
}

/**
 * Decrypt ciphertext in v{version}:{hex}:{hex} format.
 */
export function decrypt(ciphertext: string, key: EncryptionKey): Buffer {
  const { keyVersion: _version, nonce, ciphertext: ctWithTag } = parseCipherText(ciphertext);

  const tagLength = AUTH_TAG_LENGTH;
  if (ctWithTag.length < tagLength) {
    throw new Error('ciphertext too short');
  }
  const ciphertextOnly = ctWithTag.subarray(0, -tagLength);
  const authTag = ctWithTag.subarray(-tagLength);

  const decipher = createDecipheriv(ALGORITHM, key.bytes, nonce, { authTagLength: tagLength });
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(ciphertextOnly), decipher.final()]);
}

/**
 * Validate hex key format (64 chars).
 */
export function isValidKeyHex(hex: string): boolean {
  return hex.length === 64 && /^[0-9a-fA-F]+$/.test(hex);
}
