/**
 * Derives purpose-specific subkeys from a 32-byte master key using
 * libsodium's crypto_kdf_derive_from_key (BLAKE2B-based).
 *
 * This provides domain separation between layers and purposes using
 * structured parameters:
 *
 * - `context`: An 8-byte string identifying the key purpose
 *   (e.g. "cascpwdk" for password, "cascmstk" for master)
 * - `subkeyId`: A numeric identifier for the layer index (0, 1, 2, ...)
 *
 * This is equivalent in security to HKDF-Expand for our use case (deriving
 * subkeys from uniform random key material) and is purpose-built for this
 * exact pattern.
 */

import { getSodium } from './sodium.js';

/** KDF context for password-derived layer keys. */
export const KDF_CONTEXT_PASSWORD = 'cascpwdk';

/** KDF context for master key layer keys. */
export const KDF_CONTEXT_MASTER = 'cascmstk';

/** KDF context for content key layer keys. */
export const KDF_CONTEXT_CONTENT = 'cascctnt';

/**
 * Derive a subkey from a 32-byte master key.
 *
 * @param key - The 32-byte input key material.
 * @param context - An 8-character context string for domain separation.
 * @param subkeyId - A numeric subkey identifier (e.g. layer index).
 * @param lengthBytes - Desired output length in bytes (16–64).
 * @returns The derived subkey as a Uint8Array.
 */
export async function kdf(
  key: Uint8Array,
  context: string,
  subkeyId: number,
  lengthBytes: number,
): Promise<Uint8Array> {
  const sodium = await getSodium();
  return sodium.crypto_kdf_derive_from_key(lengthBytes, subkeyId, context, key);
}
