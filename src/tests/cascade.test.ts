/**
 * Integration tests for Cascade
 *
 * These tests exercise the full key hierarchy:
 *
 *   Password => (PBKDF2 + HKDF) => Password subkeys
 *     => encrypt/decrypt Master key material
 *   Master key material => (HKDF) => Master subkeys
 *     => encrypt/decrypt Content key material
 *   Content key material => (HKDF) => Content subkeys
 *     => encrypt/decrypt Data
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { cascade } from '../cascade.js';
import { presets } from '../presets.js';
import { encoding } from '../encoding.js';
import type { EncryptedData } from '../types.js';

// Use low iterations for fast tests
const TEST_ITERATIONS = 1000;

// ===========================================================================
// Full lifecycle
// ===========================================================================

test('cascade: full lifecycle: password => master key => encrypt => decrypt', async () => {
  // 1. Create a cascade with two layers of AES-256-GCM
  const c = cascade({ layers: [presets.AES_256_GCM, presets.AES_256_GCM] });

  // 2. Derive a password key
  const passwordKey = await c.derivePasswordKey({
    password: 'correct horse battery staple',
    iterations: TEST_ITERATIONS,
  });

  // 3. Generate a master key (encrypted by the password key)
  const { masterKey, encryptedMasterKey } =
    await c.generateMasterKey(passwordKey);

  // 4. Encrypt some text data
  const originalText = 'The quick brown fox jumps over the lazy dog.';
  const plaintext = encoding.textToBytes(originalText);
  const encrypted = await c.encrypt(plaintext, masterKey);

  // 5. Decrypt and verify
  const decrypted = await c.decrypt(encrypted, masterKey);
  assert.equal(encoding.bytesToText(decrypted), originalText);

  // Verify the encrypted data has the expected structure
  assert.ok(encrypted.encryptedContentKey instanceof Uint8Array);
  assert.ok(encrypted.ciphertext instanceof Uint8Array);
  assert.ok(encrypted.encryptedContentKey.length > 0);
  assert.ok(encrypted.ciphertext.length > plaintext.length);

  // Verify the encrypted master key is present
  assert.ok(encryptedMasterKey instanceof Uint8Array);
  assert.ok(encryptedMasterKey.length > 0);
});

// ===========================================================================
// Cross-session restore
// ===========================================================================

test('cascade: cross-session restore: re-derive password key, unlock master, decrypt', async () => {
  const c = cascade({
    layers: [presets.AES_256_GCM, presets.AES_256_CTR_HMAC],
  });

  // --- Session 1: initial setup ---
  const passwordKey1 = await c.derivePasswordKey({
    password: 'my-session-password',
    iterations: TEST_ITERATIONS,
  });
  const { encryptedMasterKey } = await c.generateMasterKey(passwordKey1);
  const plaintext = encoding.textToBytes('Persist me across sessions.');
  const masterKey1 = await c.unlockMasterKey(encryptedMasterKey, passwordKey1);
  const encrypted = await c.encrypt(plaintext, masterKey1);

  // --- Simulate persisting: salt, iterations, encryptedMasterKey, encrypted data ---
  const storedSalt = passwordKey1.salt;
  const storedIterations = passwordKey1.iterations;
  const storedEncryptedMasterKey = encryptedMasterKey;
  const storedEncryptedContentKey = encrypted.encryptedContentKey;
  const storedCiphertext = encrypted.ciphertext;

  // --- Session 2: restore from stored values ---
  const passwordKey2 = await c.derivePasswordKey({
    password: 'my-session-password',
    salt: storedSalt,
    iterations: storedIterations,
  });
  const masterKey2 = await c.unlockMasterKey(
    storedEncryptedMasterKey,
    passwordKey2,
  );
  const decrypted = await c.decrypt(
    {
      encryptedContentKey: storedEncryptedContentKey,
      ciphertext: storedCiphertext,
    },
    masterKey2,
  );

  assert.equal(encoding.bytesToText(decrypted), 'Persist me across sessions.');
});

// ===========================================================================
// Multiple data items with the same master key
// ===========================================================================

test('cascade: encrypt/decrypt multiple independent data items', async () => {
  const c = cascade({ layers: [presets.AES_256_GCM] });
  const passwordKey = await c.derivePasswordKey({
    password: 'multi-item',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey } = await c.generateMasterKey(passwordKey);

  // Encrypt three different data items
  const items = ['Document A', 'Document B', 'Document C'];
  const encryptedItems: EncryptedData[] = [];

  for (const item of items) {
    const encrypted = await c.encrypt(encoding.textToBytes(item), masterKey);
    encryptedItems.push(encrypted);
  }

  // Each item has a unique content key (encrypted content keys differ)
  for (let i = 0; i < encryptedItems.length; i++) {
    for (let j = i + 1; j < encryptedItems.length; j++) {
      assert.notDeepEqual(
        encryptedItems[i]!.encryptedContentKey,
        encryptedItems[j]!.encryptedContentKey,
      );
    }
  }

  // Decrypt each and verify
  for (let i = 0; i < items.length; i++) {
    const decrypted = await c.decrypt(encryptedItems[i]!, masterKey);
    assert.equal(encoding.bytesToText(decrypted), items[i]);
  }
});

// ===========================================================================
// Layer configurations
// ===========================================================================

test('cascade: single layer of AES-256-GCM', async () => {
  const c = cascade({ layers: [presets.AES_256_GCM] });
  const passwordKey = await c.derivePasswordKey({
    password: 'single',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey } = await c.generateMasterKey(passwordKey);

  const plaintext = encoding.textToBytes('Single layer test');
  const encrypted = await c.encrypt(plaintext, masterKey);
  const decrypted = await c.decrypt(encrypted, masterKey);
  assert.equal(encoding.bytesToText(decrypted), 'Single layer test');
});

test('cascade: single layer of AES-256-CTR-HMAC', async () => {
  const c = cascade({ layers: [presets.AES_256_CTR_HMAC] });
  const passwordKey = await c.derivePasswordKey({
    password: 'single-ctr',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey } = await c.generateMasterKey(passwordKey);

  const plaintext = encoding.textToBytes('CTR-HMAC single layer');
  const encrypted = await c.encrypt(plaintext, masterKey);
  const decrypted = await c.decrypt(encrypted, masterKey);
  assert.equal(encoding.bytesToText(decrypted), 'CTR-HMAC single layer');
});

test('cascade: mixed algorithms: GCM then CTR-HMAC', async () => {
  const c = cascade({
    layers: [presets.AES_256_GCM, presets.AES_256_CTR_HMAC],
  });
  const passwordKey = await c.derivePasswordKey({
    password: 'mixed',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey } = await c.generateMasterKey(passwordKey);

  const plaintext = encoding.textToBytes('Mixed algorithm cascade');
  const encrypted = await c.encrypt(plaintext, masterKey);
  const decrypted = await c.decrypt(encrypted, masterKey);
  assert.equal(encoding.bytesToText(decrypted), 'Mixed algorithm cascade');
});

test('cascade: mixed algorithms: CTR-HMAC then GCM', async () => {
  const c = cascade({
    layers: [presets.AES_256_CTR_HMAC, presets.AES_256_GCM],
  });
  const passwordKey = await c.derivePasswordKey({
    password: 'mixed-reverse',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey } = await c.generateMasterKey(passwordKey);

  const plaintext = encoding.textToBytes('Reversed mixed cascade');
  const encrypted = await c.encrypt(plaintext, masterKey);
  const decrypted = await c.decrypt(encrypted, masterKey);
  assert.equal(encoding.bytesToText(decrypted), 'Reversed mixed cascade');
});

test('cascade: many layers: 5x AES-256-GCM', async () => {
  const c = cascade({
    layers: Array(5).fill(presets.AES_256_GCM) as (
      | 'AES-256-GCM'
      | 'AES-256-CTR-HMAC'
    )[],
  });
  const passwordKey = await c.derivePasswordKey({
    password: 'five-layers',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey } = await c.generateMasterKey(passwordKey);

  const plaintext = encoding.textToBytes('Five layers deep');
  const encrypted = await c.encrypt(plaintext, masterKey);
  const decrypted = await c.decrypt(encrypted, masterKey);
  assert.equal(encoding.bytesToText(decrypted), 'Five layers deep');
});

test('cascade: many layers: 10x mixed algorithms', async () => {
  const layers = Array(10)
    .fill(null)
    .map((_, i) =>
      i % 2 === 0 ? presets.AES_256_GCM : presets.AES_256_CTR_HMAC,
    );
  const c = cascade({ layers });
  const passwordKey = await c.derivePasswordKey({
    password: 'ten-layers',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey } = await c.generateMasterKey(passwordKey);

  const plaintext = encoding.textToBytes('Ten layers deep');
  const encrypted = await c.encrypt(plaintext, masterKey);
  const decrypted = await c.decrypt(encrypted, masterKey);
  assert.equal(encoding.bytesToText(decrypted), 'Ten layers deep');
});

// ===========================================================================
// Wrong password / tampered data
// ===========================================================================

test('cascade: unlockMasterKey fails with wrong password', async () => {
  const c = cascade({ layers: [presets.AES_256_GCM] });

  const correctPwKey = await c.derivePasswordKey({
    password: 'correct',
    iterations: TEST_ITERATIONS,
  });
  const { encryptedMasterKey } = await c.generateMasterKey(correctPwKey);

  // Derive key with wrong password but same salt
  const wrongPwKey = await c.derivePasswordKey({
    password: 'wrong',
    salt: correctPwKey.salt,
    iterations: TEST_ITERATIONS,
  });

  await assert.rejects(() => c.unlockMasterKey(encryptedMasterKey, wrongPwKey));
});

test('cascade: decrypt fails with wrong master key', async () => {
  const c = cascade({ layers: [presets.AES_256_GCM] });

  // Set up two independent master keys
  const pw1 = await c.derivePasswordKey({
    password: 'key1',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey: mk1 } = await c.generateMasterKey(pw1);

  const pw2 = await c.derivePasswordKey({
    password: 'key2',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey: mk2 } = await c.generateMasterKey(pw2);

  // Encrypt with mk1, try to decrypt with mk2
  const encrypted = await c.encrypt(
    encoding.textToBytes('isolation test'),
    mk1,
  );
  await assert.rejects(() => c.decrypt(encrypted, mk2));
});

test('cascade: decrypt fails when ciphertext is tampered', async () => {
  const c = cascade({ layers: [presets.AES_256_GCM] });
  const passwordKey = await c.derivePasswordKey({
    password: 'tamper-ct',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey } = await c.generateMasterKey(passwordKey);
  const encrypted = await c.encrypt(
    encoding.textToBytes('tamper me'),
    masterKey,
  );

  // Tamper the ciphertext
  const tampered: EncryptedData = {
    encryptedContentKey: encrypted.encryptedContentKey,
    ciphertext: new Uint8Array(encrypted.ciphertext),
  };
  tampered.ciphertext[tampered.ciphertext.length - 1] ^= 0xff;

  await assert.rejects(() => c.decrypt(tampered, masterKey));
});

test('cascade: decrypt fails when encrypted content key is tampered', async () => {
  const c = cascade({ layers: [presets.AES_256_GCM] });
  const passwordKey = await c.derivePasswordKey({
    password: 'tamper-key',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey } = await c.generateMasterKey(passwordKey);
  const encrypted = await c.encrypt(
    encoding.textToBytes('tamper key'),
    masterKey,
  );

  // Tamper the encrypted content key
  const tampered: EncryptedData = {
    encryptedContentKey: new Uint8Array(encrypted.encryptedContentKey),
    ciphertext: encrypted.ciphertext,
  };
  tampered.encryptedContentKey[tampered.encryptedContentKey.length - 1] ^= 0xff;

  await assert.rejects(() => c.decrypt(tampered, masterKey));
});

test('cascade: unlockMasterKey fails when encrypted master key is tampered', async () => {
  const c = cascade({
    layers: [presets.AES_256_GCM, presets.AES_256_CTR_HMAC],
  });
  const passwordKey = await c.derivePasswordKey({
    password: 'tamper-master',
    iterations: TEST_ITERATIONS,
  });
  const { encryptedMasterKey } = await c.generateMasterKey(passwordKey);

  // Tamper the encrypted master key
  const tampered = new Uint8Array(encryptedMasterKey);
  tampered[tampered.length - 1] ^= 0xff;

  await assert.rejects(() => c.unlockMasterKey(tampered, passwordKey));
});

// ===========================================================================
// Data types
// ===========================================================================

test('cascade: encrypt/decrypt binary data with all 256 byte values', async () => {
  const c = cascade({ layers: [presets.AES_256_GCM] });
  const passwordKey = await c.derivePasswordKey({
    password: 'binary',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey } = await c.generateMasterKey(passwordKey);

  const plaintext = new Uint8Array(256);
  for (let i = 0; i < 256; i++) plaintext[i] = i;

  const encrypted = await c.encrypt(plaintext, masterKey);
  const decrypted = await c.decrypt(encrypted, masterKey);
  assert.deepEqual(decrypted, plaintext);
});

test('cascade: encrypt/decrypt empty data', async () => {
  const c = cascade({ layers: [presets.AES_256_GCM] });
  const passwordKey = await c.derivePasswordKey({
    password: 'empty',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey } = await c.generateMasterKey(passwordKey);

  const encrypted = await c.encrypt(new Uint8Array(0), masterKey);
  const decrypted = await c.decrypt(encrypted, masterKey);
  assert.equal(decrypted.length, 0);
});

test('cascade: encrypt/decrypt large data (1 MB)', async () => {
  const c = cascade({ layers: [presets.AES_256_GCM] });
  const passwordKey = await c.derivePasswordKey({
    password: 'large',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey } = await c.generateMasterKey(passwordKey);

  const plaintext = new Uint8Array(1024 * 1024);
  for (let offset = 0; offset < plaintext.length; offset += 65536) {
    globalThis.crypto.getRandomValues(
      plaintext.subarray(offset, offset + 65536),
    );
  }
  const encrypted = await c.encrypt(plaintext, masterKey);
  const decrypted = await c.decrypt(encrypted, masterKey);
  assert.deepEqual(decrypted, plaintext);
});

// ===========================================================================
// Encoding helpers in context
// ===========================================================================

test('cascade: text => encrypt => base64 => store => base64 => decrypt => text', async () => {
  const c = cascade({ layers: [presets.AES_256_GCM] });
  const passwordKey = await c.derivePasswordKey({
    password: 'encoding-test',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey } = await c.generateMasterKey(passwordKey);

  // Encrypt a text message
  const original = 'Serialize encrypted data as base64 for safe transport.';
  const encrypted = await c.encrypt(encoding.textToBytes(original), masterKey);

  // Simulate storage/transport as base64 strings
  const storedContentKey = encoding.bytesToBase64(
    encrypted.encryptedContentKey,
  );
  const storedCiphertext = encoding.bytesToBase64(encrypted.ciphertext);

  // Restore from base64 and decrypt
  const restored: EncryptedData = {
    encryptedContentKey: encoding.base64ToBytes(storedContentKey),
    ciphertext: encoding.base64ToBytes(storedCiphertext),
  };
  const decrypted = await c.decrypt(restored, masterKey);
  assert.equal(encoding.bytesToText(decrypted), original);
});

// ===========================================================================
// Configuration validation
// ===========================================================================

test('cascade: throws if no layers are provided', () => {
  assert.throws(() => cascade({ layers: [] }), /at least one layer/);
});

// ===========================================================================
// Encrypt produces unique output each call (random content keys)
// ===========================================================================

test('cascade: encrypting same data twice produces different ciphertext', async () => {
  const c = cascade({ layers: [presets.AES_256_GCM] });
  const passwordKey = await c.derivePasswordKey({
    password: 'unique-ct',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey } = await c.generateMasterKey(passwordKey);

  const plaintext = encoding.textToBytes('same data');
  const enc1 = await c.encrypt(plaintext, masterKey);
  const enc2 = await c.encrypt(plaintext, masterKey);

  // Different random content keys => different encrypted content keys
  assert.notDeepEqual(enc1.encryptedContentKey, enc2.encryptedContentKey);
  // Different IVs/nonces => different ciphertext
  assert.notDeepEqual(enc1.ciphertext, enc2.ciphertext);

  // But both decrypt to the same plaintext
  const dec1 = await c.decrypt(enc1, masterKey);
  const dec2 = await c.decrypt(enc2, masterKey);
  assert.deepEqual(dec1, dec2);
  assert.equal(encoding.bytesToText(dec1), 'same data');
});

// ===========================================================================
// Master key independence
// ===========================================================================

test('cascade: different passwords produce independent master key hierarchies', async () => {
  const c = cascade({ layers: [presets.AES_256_GCM] });

  // Two users, same cascade config, different passwords
  const pw1 = await c.derivePasswordKey({
    password: 'alice',
    iterations: TEST_ITERATIONS,
  });
  const pw2 = await c.derivePasswordKey({
    password: 'bob',
    iterations: TEST_ITERATIONS,
  });

  const { masterKey: mk1, encryptedMasterKey: emk1 } =
    await c.generateMasterKey(pw1);
  const { masterKey: mk2, encryptedMasterKey: emk2 } =
    await c.generateMasterKey(pw2);

  // Encrypted master keys are different (different password keys + different random material)
  assert.notDeepEqual(emk1, emk2);

  // Alice can encrypt and only she can decrypt
  const aliceData = await c.encrypt(encoding.textToBytes('Alice secret'), mk1);
  const aliceDecrypted = await c.decrypt(aliceData, mk1);
  assert.equal(encoding.bytesToText(aliceDecrypted), 'Alice secret');

  // Bob cannot decrypt Alice's data
  await assert.rejects(() => c.decrypt(aliceData, mk2));
});

// ===========================================================================
// Master key unlock round-trip
// ===========================================================================

test('cascade: generateMasterKey then unlockMasterKey produces functionally equivalent keys', async () => {
  const c = cascade({
    layers: [presets.AES_256_GCM, presets.AES_256_CTR_HMAC],
  });
  const passwordKey = await c.derivePasswordKey({
    password: 'round-trip-master',
    iterations: TEST_ITERATIONS,
  });

  const { masterKey: mkGenerated, encryptedMasterKey } =
    await c.generateMasterKey(passwordKey);

  const mkUnlocked = await c.unlockMasterKey(encryptedMasterKey, passwordKey);

  // Encrypt with generated key, decrypt with unlocked key (and vice versa)
  const data = encoding.textToBytes('master key equivalence');

  const enc1 = await c.encrypt(data, mkGenerated);
  const dec1 = await c.decrypt(enc1, mkUnlocked);
  assert.equal(encoding.bytesToText(dec1), 'master key equivalence');

  const enc2 = await c.encrypt(data, mkUnlocked);
  const dec2 = await c.decrypt(enc2, mkGenerated);
  assert.equal(encoding.bytesToText(dec2), 'master key equivalence');
});

// ===========================================================================
// Presets usage
// ===========================================================================

test('presets: provides correct algorithm strings', () => {
  assert.equal(presets.AES_256_GCM, 'AES-256-GCM');
  assert.equal(presets.AES_256_CTR_HMAC, 'AES-256-CTR-HMAC');
});

test('presets: can be used to configure cascade layers', async () => {
  // This test documents the recommended usage pattern
  const c = cascade({
    layers: [
      presets.AES_256_GCM,
      presets.AES_256_CTR_HMAC,
      presets.AES_256_GCM,
    ],
  });

  const passwordKey = await c.derivePasswordKey({
    password: 'presets-test',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey } = await c.generateMasterKey(passwordKey);

  const plaintext = encoding.textToBytes('Presets work!');
  const encrypted = await c.encrypt(plaintext, masterKey);
  const decrypted = await c.decrypt(encrypted, masterKey);
  assert.equal(encoding.bytesToText(decrypted), 'Presets work!');
});

// ===========================================================================
// Stress: many encryptions with same master key
// ===========================================================================

test('cascade: 50 items encrypted and decrypted with the same master key', async () => {
  const c = cascade({ layers: [presets.AES_256_GCM] });
  const passwordKey = await c.derivePasswordKey({
    password: 'stress',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey } = await c.generateMasterKey(passwordKey);

  const pairs: { original: string; encrypted: EncryptedData }[] = [];

  for (let i = 0; i < 50; i++) {
    const original = `Item ${i}: ${globalThis.crypto.getRandomValues(new Uint8Array(16)).join(',')}`;
    const encrypted = await c.encrypt(
      encoding.textToBytes(original),
      masterKey,
    );
    pairs.push({ original, encrypted });
  }

  // Decrypt all and verify, order-independent
  for (const { original, encrypted } of pairs) {
    const decrypted = await c.decrypt(encrypted, masterKey);
    assert.equal(encoding.bytesToText(decrypted), original);
  }
});

// ===========================================================================
// CTR-HMAC specific cascade tests
// ===========================================================================

test('cascade: all-CTR-HMAC cascade with tampering detection', async () => {
  const c = cascade({
    layers: [presets.AES_256_CTR_HMAC, presets.AES_256_CTR_HMAC],
  });
  const passwordKey = await c.derivePasswordKey({
    password: 'ctr-tamper',
    iterations: TEST_ITERATIONS,
  });
  const { masterKey } = await c.generateMasterKey(passwordKey);

  const plaintext = encoding.textToBytes('CTR-HMAC cascade');
  const encrypted = await c.encrypt(plaintext, masterKey);

  // Normal decrypt works
  const decrypted = await c.decrypt(encrypted, masterKey);
  assert.equal(encoding.bytesToText(decrypted), 'CTR-HMAC cascade');

  // Tampered ciphertext is detected
  const tampered: EncryptedData = {
    encryptedContentKey: encrypted.encryptedContentKey,
    ciphertext: new Uint8Array(encrypted.ciphertext),
  };
  tampered.ciphertext[20] ^= 0xff;
  await assert.rejects(() => c.decrypt(tampered, masterKey));
});
