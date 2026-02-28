/**
 * Derives a 32-byte key from a user-supplied password using Argon2id
 * via libsodium's crypto_pwhash.
 *
 * Argon2id is a memory-hard password hashing function that provides
 * resistance against GPU and ASIC-based attacks.
 *
 * If no salt is provided, a cryptographically random 16-byte salt
 * (crypto_pwhash_SALTBYTES) is generated.
 */

import { getSodium } from './sodium.js';

/** Argon2id salt length in bytes. */
export const ARGON2_SALT_LENGTH = 16;

/** Derived key length in bytes. */
const DERIVED_KEY_LENGTH = 32;

// Re-export standard parameter presets for convenience.
// These values match libsodium's crypto_pwhash constants.

/** Interactive: fast hashing for login (opsLimit=2, memLimit=64 MB). */
export const ARGON2_OPSLIMIT_INTERACTIVE = 2;
export const ARGON2_MEMLIMIT_INTERACTIVE = 67_108_864;

/** Moderate: balanced (opsLimit=3, memLimit=256 MB). */
export const ARGON2_OPSLIMIT_MODERATE = 3;
export const ARGON2_MEMLIMIT_MODERATE = 268_435_456;

/** Sensitive: high-security offline use (opsLimit=4, memLimit=1 GB). */
export const ARGON2_OPSLIMIT_SENSITIVE = 4;
export const ARGON2_MEMLIMIT_SENSITIVE = 1_073_741_824;

/** Minimum values (for testing only -- not secure for production). */
export const ARGON2_OPSLIMIT_MIN = 1;
export const ARGON2_MEMLIMIT_MIN = 8192;

/**
 * Derive a 32-byte key from a password via Argon2id.
 *
 * @returns An object containing the derived `key` (32 bytes) and the `salt`
 *          used (either the provided salt or a freshly generated one).
 */
export async function argon2(params: {
  password: string | Uint8Array;
  salt?: Uint8Array;
  opsLimit: number;
  memLimit: number;
}): Promise<{ key: Uint8Array; salt: Uint8Array }> {
  const sodium = await getSodium();

  if (params.salt && params.salt.length !== ARGON2_SALT_LENGTH) {
    throw new Error(
      `Argon2: salt must be exactly ${ARGON2_SALT_LENGTH} bytes (got ${params.salt.length})`,
    );
  }

  if (params.opsLimit < ARGON2_OPSLIMIT_MIN) {
    throw new Error(
      `Argon2: opsLimit must be at least ${ARGON2_OPSLIMIT_MIN} (got ${params.opsLimit})`,
    );
  }

  if (params.memLimit < ARGON2_MEMLIMIT_MIN) {
    throw new Error(
      `Argon2: memLimit must be at least ${ARGON2_MEMLIMIT_MIN} (got ${params.memLimit})`,
    );
  }

  const salt = params.salt ?? sodium.randombytes_buf(ARGON2_SALT_LENGTH);

  const key = sodium.crypto_pwhash(
    DERIVED_KEY_LENGTH,
    params.password,
    salt,
    params.opsLimit,
    params.memLimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );

  return { key, salt };
}
