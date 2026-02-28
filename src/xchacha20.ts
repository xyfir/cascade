/**
 * XChaCha20-Poly1305 cipher suite via libsodium
 *
 * XChaCha20-Poly1305 provides authenticated encryption with a 24-byte
 * random nonce and built-in 128-bit Poly1305 authentication tag.
 *
 * The 24-byte nonce (vs 12 for AES-GCM) is large enough to be safely
 * generated randomly without practical risk of collision, even at scale.
 *
 * Wire format: [24-byte nonce][ciphertext + 16-byte Poly1305 tag]
 */

import { getSodium } from './sodium.js';
import { encoding } from './encoding.js';
import type { CipherSuite } from './types.js';

const NONCE_LENGTH = 24;
const KEY_LENGTH = 32;
const TAG_LENGTH = 16;
const MIN_CIPHERTEXT_LENGTH = NONCE_LENGTH + TAG_LENGTH;

function validateKey(key: Uint8Array): void {
  if (key.length !== KEY_LENGTH) {
    throw new Error(
      `XChaCha20-Poly1305: key must be ${KEY_LENGTH} bytes (got ${key.length})`,
    );
  }
}

export const xchacha20: CipherSuite = {
  algorithm: 'XChaCha20-Poly1305',
  keyLength: KEY_LENGTH,

  async encrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    validateKey(key);
    const sodium = await getSodium();
    const nonce = sodium.randombytes_buf(NONCE_LENGTH);
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      data,
      null,
      null,
      nonce,
      key,
    );

    return encoding.concatBytes(nonce, ciphertext);
  },

  async decrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    validateKey(key);
    const sodium = await getSodium();

    if (data.length < MIN_CIPHERTEXT_LENGTH) {
      throw new Error('XChaCha20-Poly1305: ciphertext too short');
    }

    const nonce = data.slice(0, NONCE_LENGTH);
    const ciphertext = data.slice(NONCE_LENGTH);

    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ciphertext,
      null,
      nonce,
      key,
    );
  },
};
