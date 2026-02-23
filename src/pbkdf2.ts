/**
 * Derives a 32-byte key from a user-supplied password using PBKDF2 with
 * SHA-512. If no salt is provided, a cryptographically random 32-byte
 * salt is generated.
 */

const SALT_LENGTH = 32;
const DERIVED_KEY_BITS = 256;

import { buf } from './buf.js';

/**
 * Derive a 32-byte key from a password via PBKDF2-SHA-512.
 *
 * @returns An object containing the derived `key` (32 bytes) and the `salt`
 *          used (either the provided salt or a freshly generated one).
 */
export async function pbkdf2(params: {
  password: string;
  salt?: Uint8Array;
  iterations: number;
}): Promise<{ key: Uint8Array; salt: Uint8Array }> {
  const salt =
    params.salt ??
    globalThis.crypto.getRandomValues(new Uint8Array(SALT_LENGTH));

  const passwordBytes = new TextEncoder().encode(params.password);

  const baseKey = await globalThis.crypto.subtle.importKey(
    'raw',
    buf(passwordBytes),
    'PBKDF2',
    false,
    ['deriveBits'],
  );

  const derived = await globalThis.crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: buf(salt),
      iterations: params.iterations,
      hash: 'SHA-512',
    },
    baseKey,
    DERIVED_KEY_BITS,
  );

  return { key: new Uint8Array(derived), salt };
}
