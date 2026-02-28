/**
 * Re-exports all public-facing modules
 */

// Core factory
export { cascade } from './cascade.js';

// Algorithm cipher suites
export { aesGcm } from './aesGcm.js';
export { xchacha20 } from './xchacha20.js';

// Key derivation primitives
export {
  argon2,
  ARGON2_SALT_LENGTH,
  ARGON2_OPSLIMIT_INTERACTIVE,
  ARGON2_MEMLIMIT_INTERACTIVE,
  ARGON2_OPSLIMIT_MODERATE,
  ARGON2_MEMLIMIT_MODERATE,
  ARGON2_OPSLIMIT_SENSITIVE,
  ARGON2_MEMLIMIT_SENSITIVE,
  ARGON2_OPSLIMIT_MIN,
  ARGON2_MEMLIMIT_MIN,
} from './argon2.js';
export {
  kdf,
  KDF_CONTEXT_PASSWORD,
  KDF_CONTEXT_MASTER,
  KDF_CONTEXT_CONTENT,
} from './kdf.js';

// Encoding helpers
export { encoding } from './encoding.js';

// Utilities
export { secureWipe } from './secureWipe.js';
export { getSodium } from './sodium.js';

// Re-export MAX_LAYERS for visibility
export { MAX_LAYERS } from './cascade.js';

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
