# Cascade

**Experimental proof of concept. Not recommended for production.**

Zero-dependency isomorphic TypeScript library for cascading encryption. Encrypt data through multiple layers of symmetric ciphers with user-defined algorithm ordering.

Inspired by VeraCrypt's cascading encryption, Cascade lets you specify an arbitrary sequence of encryption algorithms. Data passes through each layer in order, with independent keys derived for every layer via HKDF.

## Key Hierarchy

```
Password (user-supplied)
  │
  ├─ PBKDF2-SHA-512 ──► 32-byte base key
  │                         │
  │                     HKDF-SHA-256 per layer ──► Password subkeys
  │
  ▼
Master Key (random 32 bytes)
  │
  ├─ Encrypted by password subkeys (stored)
  │
  ├─ HKDF-SHA-256 per layer ──► Master subkeys
  │
  ▼
Content Key (random 32 bytes, per data item)
  │
  ├─ Encrypted by master subkeys (stored with data)
  │
  ├─ HKDF-SHA-256 per layer ──► Content subkeys
  │
  ▼
Data ◄──► Encrypted by content subkeys
```

## Algorithm Presets

| Preset             | Cipher           | Authentication                  | Key Material |
| ------------------ | ---------------- | ------------------------------- | ------------ |
| `AES-256-GCM`      | AES-GCM, 256-bit | Built-in (GHASH)                | 32 bytes     |
| `AES-256-CTR-HMAC` | AES-CTR, 256-bit | HMAC-SHA-256 (encrypt-then-MAC) | 64 bytes     |

Both use the standard Web Crypto API without external dependencies.

## Usage

```typescript
import { cascade, presets, encoding } from './index.js';

// Configure a 3-layer cascade
const c = cascade({
  layers: [presets.AES_256_GCM, presets.AES_256_CTR_HMAC, presets.AES_256_GCM],
});

// Derive password key (store salt + iterations for re-derivation)
const passwordKey = await c.derivePasswordKey({
  password: 'correct horse battery staple',
  iterations: 600_000,
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
  iterations: passwordKey.iterations,
});
const restoredMasterKey = await c.unlockMasterKey(
  encryptedMasterKey, // stored from first session
  restoredPwKey,
);
const restoredData = await c.decrypt(encrypted, restoredMasterKey);
```
