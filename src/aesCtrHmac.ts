/**
 * AES-256-CTR + HMAC-SHA-256 cipher suite
 *
 * Provides authenticated encryption via the encrypt-then-MAC construction:
 *
 * 1. Encrypt with AES-256-CTR (32-byte key, 16-byte random counter block)
 * 2. Compute HMAC-SHA-256 over (counter ‖ ciphertext) using a separate 32-byte key
 * 3. Append the 32-byte MAC
 *
 * On decryption, the HMAC is verified first (constant-time comparison) before
 * any decryption is attempted.
 *
 * Key material: 64 bytes total; first 32 for AES-CTR, last 32 for HMAC.
 *
 * Wire format: [16-byte counter][ciphertext][32-byte HMAC]
 */

import type { CipherSuite } from './types.js';
import { buf } from './buf.js';

const COUNTER_LENGTH = 16;
const MAC_LENGTH = 32;
const AES_KEY_LENGTH = 32;

/**
 * Constant-time comparison of two byte arrays
 */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i]! ^ b[i]!;
  }
  return result === 0;
}

export const aesCtrHmac: CipherSuite = {
  algorithm: 'AES-256-CTR-HMAC',
  keyMaterialLength: 64,

  async importKeys(material: Uint8Array): Promise<CryptoKey[]> {
    const aesKey = await globalThis.crypto.subtle.importKey(
      'raw',
      buf(material.slice(0, AES_KEY_LENGTH)),
      { name: 'AES-CTR' },
      false,
      ['encrypt', 'decrypt'],
    );
    const hmacKey = await globalThis.crypto.subtle.importKey(
      'raw',
      buf(material.slice(AES_KEY_LENGTH)),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify'],
    );
    return [aesKey, hmacKey];
  },

  async encrypt(data: Uint8Array, keys: CryptoKey[]): Promise<Uint8Array> {
    const [aesKey, hmacKey] = keys as [CryptoKey, CryptoKey];
    const counter = globalThis.crypto.getRandomValues(
      new Uint8Array(COUNTER_LENGTH),
    );

    // Encrypt with AES-CTR - use 64 bits of the counter for incrementing
    const ciphertext = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: 'AES-CTR', counter, length: 64 },
        aesKey,
        buf(data),
      ),
    );

    // Compute HMAC over counter ‖ ciphertext (encrypt-then-MAC)
    const macInput = new Uint8Array(COUNTER_LENGTH + ciphertext.length);
    macInput.set(counter, 0);
    macInput.set(ciphertext, COUNTER_LENGTH);
    const mac = new Uint8Array(
      await globalThis.crypto.subtle.sign('HMAC', hmacKey, buf(macInput)),
    );

    // Assemble: counter ‖ ciphertext ‖ mac
    const result = new Uint8Array(
      COUNTER_LENGTH + ciphertext.length + MAC_LENGTH,
    );
    result.set(counter, 0);
    result.set(ciphertext, COUNTER_LENGTH);
    result.set(mac, COUNTER_LENGTH + ciphertext.length);
    return result;
  },

  async decrypt(data: Uint8Array, keys: CryptoKey[]): Promise<Uint8Array> {
    const [aesKey, hmacKey] = keys as [CryptoKey, CryptoKey];

    if (data.length < COUNTER_LENGTH + MAC_LENGTH) {
      throw new Error('AES-256-CTR-HMAC: ciphertext too short');
    }

    // Split components
    const counter = data.slice(0, COUNTER_LENGTH);
    const ciphertext = data.slice(COUNTER_LENGTH, data.length - MAC_LENGTH);
    const receivedMac = data.slice(data.length - MAC_LENGTH);

    // Verify HMAC before decrypting (encrypt-then-MAC: verify first)
    const macInput = new Uint8Array(COUNTER_LENGTH + ciphertext.length);
    macInput.set(counter, 0);
    macInput.set(ciphertext, COUNTER_LENGTH);
    const expectedMac = new Uint8Array(
      await globalThis.crypto.subtle.sign('HMAC', hmacKey, buf(macInput)),
    );

    if (!constantTimeEqual(receivedMac, expectedMac)) {
      throw new Error('AES-256-CTR-HMAC: HMAC verification failed');
    }

    // Decrypt
    return new Uint8Array(
      await globalThis.crypto.subtle.decrypt(
        { name: 'AES-CTR', counter, length: 64 },
        aesKey,
        buf(ciphertext),
      ),
    );
  },
};
