/**
 * Secure memory wipe via libsodium's memzero.
 *
 * Uses libsodium's sodium_memzero internally, which is designed to
 * resist compiler optimizations that might elide zeroing operations.
 */

import { getSodium } from './sodium.js';

export async function secureWipe(buffer: Uint8Array): Promise<void> {
  const sodium = await getSodium();
  sodium.memzero(buffer);
}
