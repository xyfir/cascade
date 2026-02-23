/**
 * AES-256-GCM cipher suite
 *
 * AES-GCM provides authenticated encryption with a 12-byte random IV and
 * built-in 128-bit authentication tag.
 *
 * Wire format: [12-byte IV][ciphertext + 16-byte GCM tag]
 */

import type { CipherSuite } from './types.js';
import { buf } from './buf.js';

const IV_LENGTH = 12;

export const aesGcm: CipherSuite = {
  algorithm: 'AES-256-GCM',
  keyMaterialLength: 32,

  async importKeys(material: Uint8Array): Promise<CryptoKey[]> {
    const key = await globalThis.crypto.subtle.importKey(
      'raw',
      buf(material),
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt'],
    );
    return [key];
  },

  async encrypt(data: Uint8Array, keys: CryptoKey[]): Promise<Uint8Array> {
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const ciphertext = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        keys[0]!,
        buf(data),
      ),
    );

    // Prepend IV to ciphertext
    const result = new Uint8Array(IV_LENGTH + ciphertext.length);
    result.set(iv, 0);
    result.set(ciphertext, IV_LENGTH);
    return result;
  },

  async decrypt(data: Uint8Array, keys: CryptoKey[]): Promise<Uint8Array> {
    const iv = data.slice(0, IV_LENGTH);
    const ciphertext = data.slice(IV_LENGTH);
    return new Uint8Array(
      await globalThis.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        keys[0]!,
        buf(ciphertext),
      ),
    );
  },
};
