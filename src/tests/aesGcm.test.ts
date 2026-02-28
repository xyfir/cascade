import test from 'node:test';
import assert from 'node:assert/strict';
import { aesGcm } from '../aesGcm.js';

/** Generate a random 32-byte key for AES-256-GCM. */
function generateTestKey(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(32));
}

// ---------------------------------------------------------------------------
// Basic properties
// ---------------------------------------------------------------------------

test('aesGcm: algorithm name and key length', () => {
  assert.equal(aesGcm.algorithm, 'AES-256-GCM');
  assert.equal(aesGcm.keyLength, 32);
});

// ---------------------------------------------------------------------------
// Round-trip encryption and decryption
// ---------------------------------------------------------------------------

test('aesGcm: encrypt then decrypt recovers original data', async () => {
  const key = generateTestKey();
  const plaintext = new TextEncoder().encode('Hello, Cascade!');
  const ciphertext = await aesGcm.encrypt(plaintext, key);
  const recovered = await aesGcm.decrypt(ciphertext, key);
  assert.deepEqual(recovered, plaintext);
});

test('aesGcm: round-trip with binary data containing all 256 byte values', async () => {
  const key = generateTestKey();
  const plaintext = new Uint8Array(256);
  for (let i = 0; i < 256; i++) plaintext[i] = i;
  const ciphertext = await aesGcm.encrypt(plaintext, key);
  const recovered = await aesGcm.decrypt(ciphertext, key);
  assert.deepEqual(recovered, plaintext);
});

test('aesGcm: round-trip with empty data', async () => {
  const key = generateTestKey();
  const plaintext = new Uint8Array(0);
  const ciphertext = await aesGcm.encrypt(plaintext, key);
  const recovered = await aesGcm.decrypt(ciphertext, key);
  assert.deepEqual(recovered, plaintext);
});

test('aesGcm: round-trip with large data (1 MB)', async () => {
  const key = generateTestKey();
  const plaintext = new Uint8Array(1024 * 1024);
  for (let offset = 0; offset < plaintext.length; offset += 65536) {
    globalThis.crypto.getRandomValues(
      plaintext.subarray(offset, offset + 65536),
    );
  }
  const ciphertext = await aesGcm.encrypt(plaintext, key);
  const recovered = await aesGcm.decrypt(ciphertext, key);
  assert.deepEqual(recovered, plaintext);
});

// ---------------------------------------------------------------------------
// Ciphertext properties
// ---------------------------------------------------------------------------

test('aesGcm: ciphertext is longer than plaintext (IV + tag overhead)', async () => {
  const key = generateTestKey();
  const plaintext = new TextEncoder().encode('some data');
  const ciphertext = await aesGcm.encrypt(plaintext, key);

  // 12-byte IV + plaintext length + 16-byte GCM tag
  assert.equal(ciphertext.length, 12 + plaintext.length + 16);
});

test('aesGcm: encrypting the same data twice produces different ciphertext', async () => {
  const key = generateTestKey();
  const plaintext = new TextEncoder().encode('deterministic?');
  const ct1 = await aesGcm.encrypt(plaintext, key);
  const ct2 = await aesGcm.encrypt(plaintext, key);

  // Different random IVs => different ciphertext
  assert.notDeepEqual(ct1, ct2);

  // But both decrypt to the same plaintext
  assert.deepEqual(await aesGcm.decrypt(ct1, key), plaintext);
  assert.deepEqual(await aesGcm.decrypt(ct2, key), plaintext);
});

// ---------------------------------------------------------------------------
// Authentication and error cases
// ---------------------------------------------------------------------------

test('aesGcm: decryption fails with wrong key', async () => {
  const key1 = generateTestKey();
  const key2 = generateTestKey();
  const plaintext = new TextEncoder().encode('secret');
  const ciphertext = await aesGcm.encrypt(plaintext, key1);
  await assert.rejects(() => aesGcm.decrypt(ciphertext, key2));
});

test('aesGcm: decryption fails when ciphertext is tampered', async () => {
  const key = generateTestKey();
  const plaintext = new TextEncoder().encode('tamper test');
  const ciphertext = await aesGcm.encrypt(plaintext, key);

  // Flip a byte in the ciphertext body (after the 12-byte IV)
  const tampered = new Uint8Array(ciphertext);
  tampered[14] ^= 0xff;

  await assert.rejects(() => aesGcm.decrypt(tampered, key));
});

test('aesGcm: decryption fails when IV is tampered', async () => {
  const key = generateTestKey();
  const plaintext = new TextEncoder().encode('iv tamper');
  const ciphertext = await aesGcm.encrypt(plaintext, key);

  // Flip a byte in the IV
  const tampered = new Uint8Array(ciphertext);
  tampered[0] ^= 0xff;

  await assert.rejects(() => aesGcm.decrypt(tampered, key));
});

test('aesGcm: decryption fails with truncated ciphertext', async () => {
  const key = generateTestKey();
  const plaintext = new TextEncoder().encode('truncate me');
  const ciphertext = await aesGcm.encrypt(plaintext, key);

  // Remove the last byte (breaks the GCM tag)
  const truncated = ciphertext.slice(0, ciphertext.length - 1);

  await assert.rejects(() => aesGcm.decrypt(truncated, key));
});

test('aesGcm: decryption fails with data too short', async () => {
  const key = generateTestKey();

  // Less than IV (12) + tag (16) = 28 bytes minimum
  const tooShort = new Uint8Array(20);

  await assert.rejects(
    () => aesGcm.decrypt(tooShort, key),
    /ciphertext too short/,
  );
});

test('aesGcm: encrypt rejects invalid key length', async () => {
  const shortKey = new Uint8Array(16);
  const data = new TextEncoder().encode('test');

  await assert.rejects(
    () => aesGcm.encrypt(data, shortKey),
    /key must be 32 bytes/,
  );
});

test('aesGcm: decrypt rejects invalid key length', async () => {
  const shortKey = new Uint8Array(16);
  const data = new Uint8Array(40); // long enough to pass length check

  await assert.rejects(
    () => aesGcm.decrypt(data, shortKey),
    /key must be 32 bytes/,
  );
});
