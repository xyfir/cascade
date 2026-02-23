/**
 * Re-exports all public-facing modules
 */

// Core factory
export { cascade } from './cascade.js';

// Algorithm cipher suites
export { aesGcm } from './aesGcm.js';
export { aesCtrHmac } from './aesCtrHmac.js';

// Key derivation primitives
export { pbkdf2 } from './pbkdf2.js';
export { hkdf } from './hkdf.js';

// Encoding helpers
export { encoding } from './encoding.js';

// Utilities
export { secureWipe } from './secureWipe.js';

// Algorithm presets
export { presets } from './presets.js';

// Types (compile-time only)
export type {
  Algorithm,
  CascadeConfig,
  CascadeInstance,
  CipherSuite,
  EncryptedData,
  LayerKeys,
  MasterKey,
  MasterKeyBundle,
  PasswordKey,
  PasswordKeyParams,
} from './types.js';
