import test from 'node:test';
import assert from 'node:assert/strict';
import { aesGcm } from '../aesGcm.js';

/** Generate a random 32-byte key and import it for AES-256-GCM. */
async function generateTestKeys(): Promise<CryptoKey[]> {
  const material = globalThis.crypto.getRandomValues(new Uint8Array(32));
  return aesGcm.importKeys(material);
}

// ---------------------------------------------------------------------------
// Basic properties
// ---------------------------------------------------------------------------

test('aesGcm: algorithm name and key material length', () => {
  assert.equal(aesGcm.algorithm, 'AES-256-GCM');
  assert.equal(aesGcm.keyMaterialLength, 32);
});

// ---------------------------------------------------------------------------
// Round-trip encryption and decryption
// ---------------------------------------------------------------------------

test('aesGcm: encrypt then decrypt recovers original data', async () => {
  const keys = await generateTestKeys();
  const plaintext = new TextEncoder().encode('Hello, Cascade!');
  const ciphertext = await aesGcm.encrypt(plaintext, keys);
  const recovered = await aesGcm.decrypt(ciphertext, keys);
  assert.deepEqual(recovered, plaintext);
});

test('aesGcm: round-trip with binary data containing all 256 byte values', async () => {
  const keys = await generateTestKeys();
  const plaintext = new Uint8Array(256);
  for (let i = 0; i < 256; i++) plaintext[i] = i;
  const ciphertext = await aesGcm.encrypt(plaintext, keys);
  const recovered = await aesGcm.decrypt(ciphertext, keys);
  assert.deepEqual(recovered, plaintext);
});

test('aesGcm: round-trip with empty data', async () => {
  const keys = await generateTestKeys();
  const plaintext = new Uint8Array(0);
  const ciphertext = await aesGcm.encrypt(plaintext, keys);
  const recovered = await aesGcm.decrypt(ciphertext, keys);
  assert.deepEqual(recovered, plaintext);
});

test('aesGcm: round-trip with large data (1 MB)', async () => {
  const keys = await generateTestKeys();
  const plaintext = new Uint8Array(1024 * 1024);
  for (let offset = 0; offset < plaintext.length; offset += 65536) {
    globalThis.crypto.getRandomValues(
      plaintext.subarray(offset, offset + 65536),
    );
  }
  const ciphertext = await aesGcm.encrypt(plaintext, keys);
  const recovered = await aesGcm.decrypt(ciphertext, keys);
  assert.deepEqual(recovered, plaintext);
});

// ---------------------------------------------------------------------------
// Ciphertext properties
// ---------------------------------------------------------------------------

test('aesGcm: ciphertext is longer than plaintext (IV + tag overhead)', async () => {
  const keys = await generateTestKeys();
  const plaintext = new TextEncoder().encode('some data');
  const ciphertext = await aesGcm.encrypt(plaintext, keys);

  // 12-byte IV + plaintext length + 16-byte GCM tag
  assert.equal(ciphertext.length, 12 + plaintext.length + 16);
});

test('aesGcm: encrypting the same data twice produces different ciphertext', async () => {
  const keys = await generateTestKeys();
  const plaintext = new TextEncoder().encode('deterministic?');
  const ct1 = await aesGcm.encrypt(plaintext, keys);
  const ct2 = await aesGcm.encrypt(plaintext, keys);

  // Different random IVs => different ciphertext
  assert.notDeepEqual(ct1, ct2);

  // But both decrypt to the same plaintext
  assert.deepEqual(await aesGcm.decrypt(ct1, keys), plaintext);
  assert.deepEqual(await aesGcm.decrypt(ct2, keys), plaintext);
});

// ---------------------------------------------------------------------------
// Authentication and error cases
// ---------------------------------------------------------------------------

test('aesGcm: decryption fails with wrong key', async () => {
  const keys1 = await generateTestKeys();
  const keys2 = await generateTestKeys();
  const plaintext = new TextEncoder().encode('secret');
  const ciphertext = await aesGcm.encrypt(plaintext, keys1);
  await assert.rejects(() => aesGcm.decrypt(ciphertext, keys2));
});

test('aesGcm: decryption fails when ciphertext is tampered', async () => {
  const keys = await generateTestKeys();
  const plaintext = new TextEncoder().encode('tamper test');
  const ciphertext = await aesGcm.encrypt(plaintext, keys);

  // Flip a byte in the ciphertext body (after the 12-byte IV)
  const tampered = new Uint8Array(ciphertext);
  tampered[14] ^= 0xff;

  await assert.rejects(() => aesGcm.decrypt(tampered, keys));
});

test('aesGcm: decryption fails when IV is tampered', async () => {
  const keys = await generateTestKeys();
  const plaintext = new TextEncoder().encode('iv tamper');
  const ciphertext = await aesGcm.encrypt(plaintext, keys);

  // Flip a byte in the IV
  const tampered = new Uint8Array(ciphertext);
  tampered[0] ^= 0xff;

  await assert.rejects(() => aesGcm.decrypt(tampered, keys));
});

test('aesGcm: decryption fails with truncated ciphertext', async () => {
  const keys = await generateTestKeys();
  const plaintext = new TextEncoder().encode('truncate me');
  const ciphertext = await aesGcm.encrypt(plaintext, keys);

  // Remove the last byte (breaks the GCM tag)
  const truncated = ciphertext.slice(0, ciphertext.length - 1);

  await assert.rejects(() => aesGcm.decrypt(truncated, keys));
});
