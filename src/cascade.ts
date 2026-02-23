/**
 * Core cascading encryption factory.
 *
 * `cascade()` creates a configured instance that encrypts/decrypts data
 * through multiple layers of symmetric encryption. The key hierarchy is:
 *
 *   Password => (PBKDF2 + HKDF) => Password subkeys
 *   Password subkeys => encrypt => Master key material
 *   Master key material => (HKDF) => Master subkeys
 *   Master subkeys => encrypt => Content key material
 *   Content key material => (HKDF) => Content subkeys
 *   Content subkeys => encrypt => Data
 *
 * Each layer independently derives its own CryptoKeys via HKDF with
 * domain-separated info strings, ensuring that even when the same
 * algorithm is used for multiple layers, each layer has unique keys.
 *
 * @example
 * ```ts
 * const c = cascade({ layers: ['AES-256-GCM', 'AES-256-GCM'] });
 *
 * const passwordKey = await c.derivePasswordKey({
 *   password: 'correct horse battery staple',
 *   iterations: 600_000,
 * });
 *
 * const { masterKey, encryptedMasterKey } = await c.generateMasterKey(passwordKey);
 * const encrypted = await c.encrypt(data, masterKey);
 * const decrypted = await c.decrypt(encrypted, masterKey);
 * ```
 */

import { aesGcm } from './aesGcm.js';
import { aesCtrHmac } from './aesCtrHmac.js';
import { hkdf } from './hkdf.js';
import { pbkdf2 } from './pbkdf2.js';
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
  'AES-256-CTR-HMAC': aesCtrHmac,
};

function getSuite(algorithm: Algorithm): CipherSuite {
  const suite = SUITES[algorithm];
  if (!suite) {
    throw new Error(`Unknown algorithm: ${algorithm as string}`);
  }
  return suite;
}

// ---------------------------------------------------------------------------
// Internal: key material length (32 bytes - enough for HKDF to expand from)
// ---------------------------------------------------------------------------

const RAW_KEY_MATERIAL_LENGTH = 32;

// ---------------------------------------------------------------------------
// Internal: derive per-layer CryptoKeys from raw key material
// ---------------------------------------------------------------------------

async function deriveLayerKeys(
  rawMaterial: Uint8Array,
  layers: Algorithm[],
  purpose: string,
): Promise<LayerKeys[]> {
  const layerKeys: LayerKeys[] = [];
  for (let i = 0; i < layers.length; i++) {
    const suite = getSuite(layers[i]!);
    const info = `cascade-${purpose}-layer-${i}`;
    const subkeyMaterial = await hkdf(
      rawMaterial,
      info,
      suite.keyMaterialLength,
    );
    const keys = await suite.importKeys(subkeyMaterial);
    layerKeys.push({ algorithm: layers[i]!, keys });
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
    current = await suite.encrypt(current, layerKeys[i]!.keys);
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
    current = await suite.decrypt(current, layerKeys[i]!.keys);
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

  // Validate all algorithms upfront
  for (const alg of layers) {
    getSuite(alg);
  }

  return {
    // -----------------------------------------------------------------------
    // Password key derivation
    // -----------------------------------------------------------------------

    async derivePasswordKey(params: PasswordKeyParams): Promise<PasswordKey> {
      const { key, salt } = await pbkdf2({
        password: params.password,
        salt: params.salt,
        iterations: params.iterations,
      });
      const layerKeys = await deriveLayerKeys(key, layers, 'password');
      return { salt, iterations: params.iterations, layerKeys };
    },

    // -----------------------------------------------------------------------
    // Master key generation
    // -----------------------------------------------------------------------

    async generateMasterKey(
      passwordKey: PasswordKey,
    ): Promise<MasterKeyBundle> {
      // Generate random raw master key material
      const rawMaster = globalThis.crypto.getRandomValues(
        new Uint8Array(RAW_KEY_MATERIAL_LENGTH),
      );

      // Derive per-layer subkeys for the master key
      const masterLayerKeys = await deriveLayerKeys(
        rawMaster,
        layers,
        'master',
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

      // Re-derive per-layer subkeys
      const masterLayerKeys = await deriveLayerKeys(
        rawMaster,
        layers,
        'master',
      );

      return { layerKeys: masterLayerKeys };
    },

    // -----------------------------------------------------------------------
    // Data encryption
    // -----------------------------------------------------------------------

    async encrypt(
      data: Uint8Array,
      masterKey: MasterKey,
    ): Promise<EncryptedData> {
      // Generate random raw content key material
      const rawContent = globalThis.crypto.getRandomValues(
        new Uint8Array(RAW_KEY_MATERIAL_LENGTH),
      );

      // Derive per-layer content subkeys
      const contentLayerKeys = await deriveLayerKeys(
        rawContent,
        layers,
        'content',
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

      // Re-derive per-layer content subkeys
      const contentLayerKeys = await deriveLayerKeys(
        rawContent,
        layers,
        'content',
      );

      // Decrypt the actual data through the content key cascade
      return cascadeDecrypt(encryptedData.ciphertext, layers, contentLayerKeys);
    },
  };
}
