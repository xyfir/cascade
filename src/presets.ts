/**
 * Algorithm presets
 *
 * Use these when configuring cascade layers instead of raw string literals.
 */

import type { Algorithm } from './types.js';

export const presets = {
  AES_256_GCM: 'AES-256-GCM' as const satisfies Algorithm,
  AES_256_CTR_HMAC: 'AES-256-CTR-HMAC' as const satisfies Algorithm,
};
