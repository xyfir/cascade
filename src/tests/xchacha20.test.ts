import test from 'node:test';
import assert from 'node:assert/strict';
import { xchacha20 } from '../xchacha20.js';
import { getSodium } from '../sodium.js';

/** Generate a random 32-byte key for XChaCha20-Poly1305. */
async function generateTestKey(): Promise<Uint8Array> {
  const sodium = await getSodium();
  return sodium.randombytes_buf(32);
}

// ---------------------------------------------------------------------------
// Basic properties
// ---------------------------------------------------------------------------

test('xchacha20: algorithm name and key length', () => {
  assert.equal(xchacha20.algorithm, 'XChaCha20-Poly1305');
  assert.equal(xchacha20.keyLength, 32);
});

// ---------------------------------------------------------------------------
// Round-trip encryption and decryption
// ---------------------------------------------------------------------------

test('xchacha20: encrypt then decrypt recovers original data', async () => {
  const key = await generateTestKey();
  const plaintext = new TextEncoder().encode('Hello, XChaCha20!');
  const ciphertext = await xchacha20.encrypt(plaintext, key);
  const recovered = await xchacha20.decrypt(ciphertext, key);
  assert.deepEqual(recovered, plaintext);
});

test('xchacha20: round-trip with binary data containing all 256 byte values', async () => {
  const key = await generateTestKey();
  const plaintext = new Uint8Array(256);
  for (let i = 0; i < 256; i++) plaintext[i] = i;
  const ciphertext = await xchacha20.encrypt(plaintext, key);
  const recovered = await xchacha20.decrypt(ciphertext, key);
  assert.deepEqual(recovered, plaintext);
});

test('xchacha20: round-trip with empty data', async () => {
  const key = await generateTestKey();
  const plaintext = new Uint8Array(0);
  const ciphertext = await xchacha20.encrypt(plaintext, key);
  const recovered = await xchacha20.decrypt(ciphertext, key);
  assert.deepEqual(recovered, plaintext);
});

test('xchacha20: round-trip with large data (1 MB)', async () => {
  const key = await generateTestKey();
  const plaintext = new Uint8Array(1024 * 1024);
  for (let offset = 0; offset < plaintext.length; offset += 65536) {
    globalThis.crypto.getRandomValues(
      plaintext.subarray(offset, offset + 65536),
    );
  }
  const ciphertext = await xchacha20.encrypt(plaintext, key);
  const recovered = await xchacha20.decrypt(ciphertext, key);
  assert.deepEqual(recovered, plaintext);
});

// ---------------------------------------------------------------------------
// Ciphertext properties
// ---------------------------------------------------------------------------

test('xchacha20: ciphertext is longer than plaintext (nonce + tag overhead)', async () => {
  const key = await generateTestKey();
  const plaintext = new TextEncoder().encode('some data');
  const ciphertext = await xchacha20.encrypt(plaintext, key);

  // 24-byte nonce + plaintext length + 16-byte Poly1305 tag
  assert.equal(ciphertext.length, 24 + plaintext.length + 16);
});

test('xchacha20: encrypting the same data twice produces different ciphertext', async () => {
  const key = await generateTestKey();
  const plaintext = new TextEncoder().encode('deterministic?');
  const ct1 = await xchacha20.encrypt(plaintext, key);
  const ct2 = await xchacha20.encrypt(plaintext, key);

  // Different random nonces => different ciphertext
  assert.notDeepEqual(ct1, ct2);

  // But both decrypt to the same plaintext
  assert.deepEqual(await xchacha20.decrypt(ct1, key), plaintext);
  assert.deepEqual(await xchacha20.decrypt(ct2, key), plaintext);
});

// ---------------------------------------------------------------------------
// Authentication and error cases
// ---------------------------------------------------------------------------

test('xchacha20: decryption fails with wrong key', async () => {
  const key1 = await generateTestKey();
  const key2 = await generateTestKey();
  const plaintext = new TextEncoder().encode('secret');
  const ciphertext = await xchacha20.encrypt(plaintext, key1);
  await assert.rejects(() => xchacha20.decrypt(ciphertext, key2));
});

test('xchacha20: decryption fails when ciphertext is tampered', async () => {
  const key = await generateTestKey();
  const plaintext = new TextEncoder().encode('tamper test');
  const ciphertext = await xchacha20.encrypt(plaintext, key);

  // Flip a byte in the ciphertext body (after the 24-byte nonce)
  const tampered = new Uint8Array(ciphertext);
  tampered[28] ^= 0xff;

  await assert.rejects(() => xchacha20.decrypt(tampered, key));
});

test('xchacha20: decryption fails when nonce is tampered', async () => {
  const key = await generateTestKey();
  const plaintext = new TextEncoder().encode('nonce tamper');
  const ciphertext = await xchacha20.encrypt(plaintext, key);

  // Flip a byte in the nonce
  const tampered = new Uint8Array(ciphertext);
  tampered[0] ^= 0xff;

  await assert.rejects(() => xchacha20.decrypt(tampered, key));
});

test('xchacha20: decryption fails with truncated ciphertext', async () => {
  const key = await generateTestKey();
  const plaintext = new TextEncoder().encode('truncate me');
  const ciphertext = await xchacha20.encrypt(plaintext, key);

  // Remove the last byte (breaks the Poly1305 tag)
  const truncated = ciphertext.slice(0, ciphertext.length - 1);

  await assert.rejects(() => xchacha20.decrypt(truncated, key));
});

test('xchacha20: decryption fails with data too short', async () => {
  const key = await generateTestKey();

  // Less than nonce (24) + tag (16) = 40 bytes minimum
  const tooShort = new Uint8Array(30);

  await assert.rejects(
    () => xchacha20.decrypt(tooShort, key),
    /ciphertext too short/,
  );
});

test('xchacha20: encrypt rejects invalid key length', async () => {
  const shortKey = new Uint8Array(16);
  const data = new TextEncoder().encode('test');

  await assert.rejects(
    () => xchacha20.encrypt(data, shortKey),
    /key must be 32 bytes/,
  );
});

test('xchacha20: decrypt rejects invalid key length', async () => {
  const shortKey = new Uint8Array(16);
  const data = new Uint8Array(50); // long enough to pass length check

  await assert.rejects(
    () => xchacha20.decrypt(data, shortKey),
    /key must be 32 bytes/,
  );
});
