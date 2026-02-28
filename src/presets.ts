/**
 * Algorithm presets
 *
 * Use these when configuring cascade layers instead of raw string literals.
 */

import type { Algorithm } from './types.js';

export const presets = {
  AES_256_GCM: 'AES-256-GCM' as const satisfies Algorithm,
  XCHACHA20_POLY1305: 'XChaCha20-Poly1305' as const satisfies Algorithm,
};
