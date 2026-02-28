/**
 * AES-256-GCM cipher suite (via Web Crypto API)
 *
 * AES-GCM provides authenticated encryption with a 12-byte random IV and
 * built-in 128-bit authentication tag. Uses the Web Crypto API internally
 * to ensure isomorphic support across all platforms (Node.js, browsers,
 * edge runtimes).
 *
 * Wire format: [12-byte IV][ciphertext + 16-byte GCM tag]
 */

import { encoding } from './encoding.js';
import type { CipherSuite } from './types.js';

const IV_LENGTH = 12;
const KEY_LENGTH = 32;
const TAG_LENGTH = 16;
const MIN_CIPHERTEXT_LENGTH = IV_LENGTH + TAG_LENGTH;

/** Cast Uint8Array for Web Crypto API compatibility. */
function buf(data: Uint8Array): Uint8Array<ArrayBuffer> {
  return data as Uint8Array<ArrayBuffer>;
}

/**
 * Import raw 32-byte key material as a Web Crypto CryptoKey for AES-GCM.
 */
async function importKey(
  material: Uint8Array,
  usage: 'encrypt' | 'decrypt',
): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey(
    'raw',
    buf(material),
    { name: 'AES-GCM' },
    false,
    [usage],
  );
}

function validateKey(key: Uint8Array): void {
  if (key.length !== KEY_LENGTH) {
    throw new Error(
      `AES-256-GCM: key must be ${KEY_LENGTH} bytes (got ${key.length})`,
    );
  }
}

export const aesGcm: CipherSuite = {
  algorithm: 'AES-256-GCM',
  keyLength: KEY_LENGTH,

  async encrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    validateKey(key);
    const cryptoKey = await importKey(key, 'encrypt');
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const ciphertext = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        buf(data),
      ),
    );

    return encoding.concatBytes(iv, ciphertext);
  },

  async decrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    validateKey(key);

    if (data.length < MIN_CIPHERTEXT_LENGTH) {
      throw new Error('AES-256-GCM: ciphertext too short');
    }

    const cryptoKey = await importKey(key, 'decrypt');
    const iv = data.slice(0, IV_LENGTH);
    const ciphertext = data.slice(IV_LENGTH);
    return new Uint8Array(
      await globalThis.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        ciphertext,
      ),
    );
  },
};
