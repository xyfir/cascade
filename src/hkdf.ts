/**
 * Expands base key material into purpose-specific subkeys using HKDF
 * (RFC 5869) with SHA-256. Uses a zero-filled salt (the extraction step
 * is assumed to have already occurred via PBKDF2 or random generation).
 *
 * The `info` parameter provides domain separation between layers and
 * purposes, following the convention:
 *
 *   cascade-{purpose}-layer-{index}
 *
 * For example: "cascade-password-layer-0", "cascade-master-layer-2"
 */

const ZERO_SALT = new Uint8Array(32);

import { buf } from './buf.js';

/**
 * Derive a subkey from base key material using HKDF-SHA-256.
 *
 * @param keyMaterial - The input keying material (e.g. 32 bytes from PBKDF2 or random).
 * @param info - A context/purpose string for domain separation.
 * @param lengthBytes - Desired output length in bytes.
 * @returns The derived subkey as a Uint8Array.
 */
export async function hkdf(
  keyMaterial: Uint8Array,
  info: string,
  lengthBytes: number,
): Promise<Uint8Array> {
  const infoBytes = new TextEncoder().encode(info);

  const baseKey = await globalThis.crypto.subtle.importKey(
    'raw',
    buf(keyMaterial),
    'HKDF',
    false,
    ['deriveBits'],
  );

  const derived = await globalThis.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: buf(ZERO_SALT),
      info: buf(infoBytes),
    },
    baseKey,
    lengthBytes * 8,
  );

  return new Uint8Array(derived);
}
