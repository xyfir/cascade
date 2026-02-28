# Cascade

**Experimental proof of concept. Not recommended for production.**

Isomorphic TypeScript library for cascading encryption. Encrypt data through multiple layers of symmetric ciphers with user-defined algorithm ordering.

Inspired by VeraCrypt's cascading encryption, Cascade lets you specify an arbitrary sequence of encryption algorithms. Data passes through each layer in order, with independent keys derived for every layer.

Uses **libsodium** (via `libsodium-wrappers-sumo`) for Argon2id password hashing, XChaCha20-Poly1305 encryption, KDF, and secure memory wiping. Uses the **Web Crypto API** for AES-256-GCM encryption (ensuring isomorphic support across all platforms).

## Key Hierarchy

```
Password (user-supplied)
  |
  +-- Argon2id --> 32-byte base key
  |                  |
  |              crypto_kdf per layer --> Password subkeys
  |
  v
Master Key (random 32 bytes)
  |
  +-- Encrypted by password subkeys (stored)
  |
  +-- crypto_kdf per layer --> Master subkeys
  |
  v
Content Key (random 32 bytes, per data item)
  |
  +-- Encrypted by master subkeys (stored with data)
  |
  +-- crypto_kdf per layer --> Content subkeys
  |
  v
Data <--> Encrypted by content subkeys
```

## Algorithm Presets

| Preset               | Cipher             | Authentication      | Key Length |
| -------------------- | ------------------ | ------------------- | ---------- |
| `AES-256-GCM`        | AES-GCM, 256-bit   | Built-in (GHASH)    | 32 bytes   |
| `XChaCha20-Poly1305` | XChaCha20, 256-bit | Built-in (Poly1305) | 32 bytes   |

## Usage

```typescript
import {
  cascade,
  presets,
  encoding,
  ARGON2_OPSLIMIT_MODERATE,
  ARGON2_MEMLIMIT_MODERATE,
} from './index.js';

// Configure a 3-layer cascade
const c = cascade({
  layers: [
    presets.AES_256_GCM,
    presets.XCHACHA20_POLY1305,
    presets.AES_256_GCM,
  ],
});

// Derive password key (store salt + opsLimit + memLimit for re-derivation)
const passwordKey = await c.derivePasswordKey({
  password: 'correct horse battery staple',
  opsLimit: ARGON2_OPSLIMIT_MODERATE,
  memLimit: ARGON2_MEMLIMIT_MODERATE,
});

// Generate master key (store encryptedMasterKey)
const { masterKey, encryptedMasterKey } =
  await c.generateMasterKey(passwordKey);

// Encrypt data
const plaintext = encoding.textToBytes('Secret document');
const encrypted = await c.encrypt(plaintext, masterKey);

// Decrypt data
const decrypted = await c.decrypt(encrypted, masterKey);
console.log(encoding.bytesToText(decrypted)); // "Secret document"

// --- Later session: restore from stored values ---
const restoredPwKey = await c.derivePasswordKey({
  password: 'correct horse battery staple',
  salt: passwordKey.salt, // stored from first session
  opsLimit: passwordKey.opsLimit,
  memLimit: passwordKey.memLimit,
});
const restoredMasterKey = await c.unlockMasterKey(
  encryptedMasterKey, // stored from first session
  restoredPwKey,
);
const restoredData = await c.decrypt(encrypted, restoredMasterKey);
```
