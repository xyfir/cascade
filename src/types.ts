// ---------------------------------------------------------------------------
// Algorithm identifiers
// ---------------------------------------------------------------------------

/** Supported symmetric cipher algorithms for cascading encryption layers. */
export type Algorithm = 'AES-256-GCM' | 'AES-256-CTR-HMAC';

// ---------------------------------------------------------------------------
// Cipher suite interface
// ---------------------------------------------------------------------------

/**
 * A cipher suite encapsulates the encrypt/decrypt logic for one algorithm.
 * Each suite knows how much key material it needs and how to import, encrypt,
 * and decrypt with that material.
 */
export interface CipherSuite {
  /** Algorithm identifier. */
  readonly algorithm: Algorithm;

  /** Number of raw bytes of key material required (e.g. 32 for AES-GCM, 64 for CTR+HMAC). */
  readonly keyMaterialLength: number;

  /** Import raw key material into one or more CryptoKeys for use with this suite. */
  importKeys(material: Uint8Array): Promise<CryptoKey[]>;

  /** Encrypt data. Returns a self-contained blob (IV/nonce + ciphertext + tag). */
  encrypt(data: Uint8Array, keys: CryptoKey[]): Promise<Uint8Array>;

  /** Decrypt a blob produced by `encrypt`. Throws on authentication failure. */
  decrypt(data: Uint8Array, keys: CryptoKey[]): Promise<Uint8Array>;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * Configuration for a Cascade instance.
 *
 * `layers` defines the ordered list of algorithms to cascade through.
 * The same algorithm may appear multiple times (e.g. 10x AES-256-GCM).
 */
export interface CascadeConfig {
  layers: Algorithm[];
}

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------

/** Derived CryptoKeys for a single cascade layer. */
export interface LayerKeys {
  algorithm: Algorithm;
  keys: CryptoKey[];
}

/**
 * Parameters for deriving a password key via PBKDF2.
 *
 * If `salt` is omitted, a cryptographically random 32-byte salt is generated.
 */
export interface PasswordKeyParams {
  password: string;
  iterations: number;
  salt?: Uint8Array;
}

/**
 * A password-derived key with per-layer subkeys.
 *
 * Store `salt` and `iterations` for future re-derivation. The `layerKeys`
 * are session-only (derived fresh each time from the password).
 */
export interface PasswordKey {
  salt: Uint8Array;
  iterations: number;
  layerKeys: LayerKeys[];
}

/**
 * A randomly generated master key with per-layer subkeys.
 *
 * `layerKeys` are session-only so the raw material is never exposed.
 * Store only the `encryptedMasterKey` from a `MasterKeyBundle`.
 */
export interface MasterKey {
  layerKeys: LayerKeys[];
}

/**
 * Returned when generating a new master key.
 *
 * - `masterKey`: ready-to-use master key for the current session.
 * - `encryptedMasterKey`: the raw master material encrypted through the
 *   password key cascade. Persist this for future sessions.
 */
export interface MasterKeyBundle {
  masterKey: MasterKey;
  encryptedMasterKey: Uint8Array;
}

/**
 * Encrypted data bundle.
 *
 * - `encryptedContentKey`: content key material encrypted through the master
 *   key cascade.
 * - `ciphertext`: the actual data encrypted through the content key cascade.
 *
 * Both fields must be stored together to later decrypt the data.
 */
export interface EncryptedData {
  encryptedContentKey: Uint8Array;
  ciphertext: Uint8Array;
}

/**
 * The public API surface returned by `cascade()`.
 */
export interface CascadeInstance {
  /** Derive a password key from a user-supplied password via PBKDF2 + HKDF. */
  derivePasswordKey(params: PasswordKeyParams): Promise<PasswordKey>;

  /** Generate a new random master key and encrypt it with the password key. */
  generateMasterKey(passwordKey: PasswordKey): Promise<MasterKeyBundle>;

  /** Unlock a previously encrypted master key using the password key. */
  unlockMasterKey(
    encryptedMasterKey: Uint8Array,
    passwordKey: PasswordKey,
  ): Promise<MasterKey>;

  /** Encrypt arbitrary binary data using the master key. */
  encrypt(data: Uint8Array, masterKey: MasterKey): Promise<EncryptedData>;

  /** Decrypt data previously encrypted with `encrypt`. */
  decrypt(
    encryptedData: EncryptedData,
    masterKey: MasterKey,
  ): Promise<Uint8Array>;
}
