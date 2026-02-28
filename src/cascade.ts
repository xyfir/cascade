/**
 * Core cascading encryption factory.
 *
 * `cascade()` creates a configured instance that encrypts/decrypts data
 * through multiple layers of symmetric encryption. The key hierarchy is:
 *
 *   Password => (Argon2id + KDF) => Password subkeys
 *   Password subkeys => encrypt => Master key material
 *   Master key material => (KDF) => Master subkeys
 *   Master subkeys => encrypt => Content key material
 *   Content key material => (KDF) => Content subkeys
 *   Content subkeys => encrypt => Data
 *
 * Each layer independently derives its own key via libsodium's
 * crypto_kdf_derive_from_key with domain-separated context strings and
 * layer indices, ensuring that even when the same algorithm is used for
 * multiple layers, each layer has unique keys.
 *
 * @example
 * ```ts
 * import { cascade, presets, ARGON2_OPSLIMIT_MODERATE, ARGON2_MEMLIMIT_MODERATE } from './index.js';
 *
 * const c = cascade({ layers: ['AES-256-GCM', 'XChaCha20-Poly1305'] });
 *
 * const passwordKey = await c.derivePasswordKey({
 *   password: 'correct horse battery staple',
 *   opsLimit: ARGON2_OPSLIMIT_MODERATE,
 *   memLimit: ARGON2_MEMLIMIT_MODERATE,
 * });
 *
 * const { masterKey, encryptedMasterKey } = await c.generateMasterKey(passwordKey);
 * const encrypted = await c.encrypt(data, masterKey);
 * const decrypted = await c.decrypt(encrypted, masterKey);
 * ```
 */

import { aesGcm } from './aesGcm.js';
import { xchacha20 } from './xchacha20.js';
import {
  kdf,
  KDF_CONTEXT_PASSWORD,
  KDF_CONTEXT_MASTER,
  KDF_CONTEXT_CONTENT,
} from './kdf.js';
import { argon2 } from './argon2.js';
import { getSodium } from './sodium.js';
import { secureWipe } from './secureWipe.js';
import type {
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

// ---------------------------------------------------------------------------
// Internal: algorithm registry
// ---------------------------------------------------------------------------

const SUITES: Record<Algorithm, CipherSuite> = {
  'AES-256-GCM': aesGcm,
  'XChaCha20-Poly1305': xchacha20,
};

function getSuite(algorithm: Algorithm): CipherSuite {
  const suite = SUITES[algorithm];
  if (!suite) {
    throw new Error(`Unknown algorithm: ${algorithm as string}`);
  }
  return suite;
}

// ---------------------------------------------------------------------------
// Internal: key material length (32 bytes)
// ---------------------------------------------------------------------------

const RAW_KEY_MATERIAL_LENGTH = 32;

/**
 * Maximum number of cascade layers allowed.
 * Prevents DoS via excessive layer counts.
 */
export const MAX_LAYERS = 10;

// ---------------------------------------------------------------------------
// Internal: derive per-layer keys from raw key material
// ---------------------------------------------------------------------------

async function deriveLayerKeys(
  rawMaterial: Uint8Array,
  layers: Algorithm[],
  context: string,
): Promise<LayerKeys[]> {
  const layerKeys: LayerKeys[] = [];
  for (let i = 0; i < layers.length; i++) {
    const suite = getSuite(layers[i]!);
    const key = await kdf(rawMaterial, context, i, suite.keyLength);
    layerKeys.push({ algorithm: layers[i]!, key });
  }
  return layerKeys;
}

// ---------------------------------------------------------------------------
// Internal: cascading encrypt / decrypt
// ---------------------------------------------------------------------------

async function cascadeEncrypt(
  data: Uint8Array,
  layers: Algorithm[],
  layerKeys: LayerKeys[],
): Promise<Uint8Array> {
  let current = data;
  for (let i = 0; i < layers.length; i++) {
    const suite = getSuite(layers[i]!);
    current = await suite.encrypt(current, layerKeys[i]!.key);
  }
  return current;
}

async function cascadeDecrypt(
  data: Uint8Array,
  layers: Algorithm[],
  layerKeys: LayerKeys[],
): Promise<Uint8Array> {
  let current = data;
  // Decrypt in reverse layer order
  for (let i = layers.length - 1; i >= 0; i--) {
    const suite = getSuite(layers[i]!);
    current = await suite.decrypt(current, layerKeys[i]!.key);
  }
  return current;
}

// ---------------------------------------------------------------------------
// Public API: cascade factory
// ---------------------------------------------------------------------------

/**
 * Create a Cascade instance configured with the specified encryption layers.
 *
 * @param config - Configuration specifying the ordered list of algorithms.
 * @returns An object with methods for key derivation, encryption, and decryption.
 * @throws If `config.layers` is empty or contains unknown algorithms.
 */
export function cascade(config: CascadeConfig): CascadeInstance {
  const { layers } = config;

  if (layers.length === 0) {
    throw new Error('Cascade requires at least one layer');
  }

  if (layers.length > MAX_LAYERS) {
    throw new Error(
      `Cascade supports at most ${MAX_LAYERS} layers (got ${layers.length})`,
    );
  }

  // Validate all algorithms upfront
  for (const alg of layers) {
    getSuite(alg);
  }

  return {
    // -----------------------------------------------------------------------
    // Password key derivation
    // -----------------------------------------------------------------------

    async derivePasswordKey(params: PasswordKeyParams): Promise<PasswordKey> {
      const { key, salt } = await argon2({
        password: params.password,
        salt: params.salt,
        opsLimit: params.opsLimit,
        memLimit: params.memLimit,
      });
      try {
        const layerKeys = await deriveLayerKeys(
          key,
          layers,
          KDF_CONTEXT_PASSWORD,
        );
        return {
          salt,
          opsLimit: params.opsLimit,
          memLimit: params.memLimit,
          layerKeys,
        };
      } finally {
        await secureWipe(key);
      }
    },

    // -----------------------------------------------------------------------
    // Master key generation
    // -----------------------------------------------------------------------

    async generateMasterKey(
      passwordKey: PasswordKey,
    ): Promise<MasterKeyBundle> {
      const sodium = await getSodium();

      // Generate random raw master key material
      const rawMaster = sodium.randombytes_buf(RAW_KEY_MATERIAL_LENGTH);

      try {
        // Derive per-layer subkeys for the master key
        const masterLayerKeys = await deriveLayerKeys(
          rawMaster,
          layers,
          KDF_CONTEXT_MASTER,
        );

        // Encrypt the raw master material through the password key cascade
        const encryptedMasterKey = await cascadeEncrypt(
          rawMaster,
          layers,
          passwordKey.layerKeys,
        );

        return {
          masterKey: { layerKeys: masterLayerKeys },
          encryptedMasterKey,
        };
      } finally {
        await secureWipe(rawMaster);
      }
    },

    // -----------------------------------------------------------------------
    // Master key unlocking
    // -----------------------------------------------------------------------

    async unlockMasterKey(
      encryptedMasterKey: Uint8Array,
      passwordKey: PasswordKey,
    ): Promise<MasterKey> {
      // Decrypt the raw master material through the password key cascade
      const rawMaster = await cascadeDecrypt(
        encryptedMasterKey,
        layers,
        passwordKey.layerKeys,
      );

      try {
        // Re-derive per-layer subkeys
        const masterLayerKeys = await deriveLayerKeys(
          rawMaster,
          layers,
          KDF_CONTEXT_MASTER,
        );

        return { layerKeys: masterLayerKeys };
      } finally {
        await secureWipe(rawMaster);
      }
    },

    // -----------------------------------------------------------------------
    // Data encryption
    // -----------------------------------------------------------------------

    async encrypt(
      data: Uint8Array,
      masterKey: MasterKey,
    ): Promise<EncryptedData> {
      const sodium = await getSodium();

      // Generate random raw content key material
      const rawContent = sodium.randombytes_buf(RAW_KEY_MATERIAL_LENGTH);

      try {
        // Derive per-layer content subkeys
        const contentLayerKeys = await deriveLayerKeys(
          rawContent,
          layers,
          KDF_CONTEXT_CONTENT,
        );

        // Encrypt the raw content key through the master key cascade
        const encryptedContentKey = await cascadeEncrypt(
          rawContent,
          layers,
          masterKey.layerKeys,
        );

        // Encrypt the actual data through the content key cascade
        const ciphertext = await cascadeEncrypt(data, layers, contentLayerKeys);

        return { encryptedContentKey, ciphertext };
      } finally {
        await secureWipe(rawContent);
      }
    },

    // -----------------------------------------------------------------------
    // Data decryption
    // -----------------------------------------------------------------------

    async decrypt(
      encryptedData: EncryptedData,
      masterKey: MasterKey,
    ): Promise<Uint8Array> {
      // Decrypt the raw content key through the master key cascade
      const rawContent = await cascadeDecrypt(
        encryptedData.encryptedContentKey,
        layers,
        masterKey.layerKeys,
      );

      try {
        // Re-derive per-layer content subkeys
        const contentLayerKeys = await deriveLayerKeys(
          rawContent,
          layers,
          KDF_CONTEXT_CONTENT,
        );

        // Decrypt the actual data through the content key cascade
        return await cascadeDecrypt(
          encryptedData.ciphertext,
          layers,
          contentLayerKeys,
        );
      } finally {
        await secureWipe(rawContent);
      }
    },

    // -----------------------------------------------------------------------
    // Password change
    // -----------------------------------------------------------------------

    async changePassword(
      encryptedMasterKey: Uint8Array,
      oldPasswordKey: PasswordKey,
      newPasswordKey: PasswordKey,
    ): Promise<Uint8Array> {
      // Decrypt the raw master material with the old password key
      const rawMaster = await cascadeDecrypt(
        encryptedMasterKey,
        layers,
        oldPasswordKey.layerKeys,
      );

      try {
        // Re-encrypt with the new password key
        return await cascadeEncrypt(
          rawMaster,
          layers,
          newPasswordKey.layerKeys,
        );
      } finally {
        await secureWipe(rawMaster);
      }
    },

    // -----------------------------------------------------------------------
    // Key lifecycle helpers
    // -----------------------------------------------------------------------

    async wipePasswordKey(passwordKey: PasswordKey): Promise<void> {
      for (const lk of passwordKey.layerKeys) {
        await secureWipe(lk.key);
      }
    },

    async wipeMasterKey(masterKey: MasterKey): Promise<void> {
      for (const lk of masterKey.layerKeys) {
        await secureWipe(lk.key);
      }
    },
  };
}
