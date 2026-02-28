// ---------------------------------------------------------------------------
// Algorithm identifiers
// ---------------------------------------------------------------------------

/** Supported symmetric cipher algorithms for cascading encryption layers. */
export type Algorithm = 'AES-256-GCM' | 'XChaCha20-Poly1305';

// ---------------------------------------------------------------------------
// Cipher suite interface
// ---------------------------------------------------------------------------

/**
 * A cipher suite encapsulates the encrypt/decrypt logic for one algorithm.
 * Each suite knows its key length and how to encrypt/decrypt with raw key
 * material (Uint8Array).
 */
export interface CipherSuite {
  /** Algorithm identifier. */
  readonly algorithm: Algorithm;

  /** Number of bytes of key material required (32 for both supported algorithms). */
  readonly keyLength: number;

  /** Encrypt data. Returns a self-contained blob (nonce + ciphertext + tag). */
  encrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array>;

  /** Decrypt a blob produced by `encrypt`. Throws on authentication failure. */
  decrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array>;
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

/** Derived key material for a single cascade layer. */
export interface LayerKeys {
  algorithm: Algorithm;
  key: Uint8Array;
}

/**
 * Parameters for deriving a password key via Argon2id.
 *
 * If `salt` is omitted, a cryptographically random 16-byte salt is generated.
 * Use the exported ARGON2_* constants from `argon2.ts` for `opsLimit` and
 * `memLimit` values.
 */
export interface PasswordKeyParams {
  /**
   * User password. Prefer `Uint8Array` over `string` when possible —
   * JavaScript strings are immutable and cannot be wiped from memory.
   * When a `Uint8Array` is provided, the caller is responsible for
   * wiping it after `derivePasswordKey()` resolves.
   */
  password: string | Uint8Array;
  opsLimit: number;
  memLimit: number;
  salt?: Uint8Array;
}

/**
 * A password-derived key with per-layer subkeys.
 *
 * Store `salt`, `opsLimit`, and `memLimit` for future re-derivation. The
 * `layerKeys` are session-only (derived fresh each time from the password).
 */
export interface PasswordKey {
  salt: Uint8Array;
  opsLimit: number;
  memLimit: number;
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
  /** Derive a password key from a user-supplied password via Argon2id + KDF. */
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

  /**
   * Re-encrypt the master key under a new password.
   *
   * Decrypts the raw master material with `oldPasswordKey`, then re-encrypts
   * it with `newPasswordKey`. Returns the new encrypted master key blob.
   */
  changePassword(
    encryptedMasterKey: Uint8Array,
    oldPasswordKey: PasswordKey,
    newPasswordKey: PasswordKey,
  ): Promise<Uint8Array>;

  /** Securely wipe all layer key material from a PasswordKey. */
  wipePasswordKey(passwordKey: PasswordKey): Promise<void>;

  /** Securely wipe all layer key material from a MasterKey. */
  wipeMasterKey(masterKey: MasterKey): Promise<void>;
}
