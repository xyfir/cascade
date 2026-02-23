import test from 'node:test';
import assert from 'node:assert/strict';
import { aesCtrHmac } from '../aesCtrHmac.js';

/** Generate random 64-byte key material and import for AES-CTR + HMAC. */
async function generateTestKeys(): Promise<CryptoKey[]> {
  const material = globalThis.crypto.getRandomValues(new Uint8Array(64));
  return aesCtrHmac.importKeys(material);
}

// ---------------------------------------------------------------------------
// Basic properties
// ---------------------------------------------------------------------------

test('aesCtrHmac: algorithm name and key material length', () => {
  assert.equal(aesCtrHmac.algorithm, 'AES-256-CTR-HMAC');
  assert.equal(aesCtrHmac.keyMaterialLength, 64);
});

// ---------------------------------------------------------------------------
// Round-trip encryption and decryption
// ---------------------------------------------------------------------------

test('aesCtrHmac: encrypt then decrypt recovers original data', async () => {
  const keys = await generateTestKeys();
  const plaintext = new TextEncoder().encode('Hello from CTR-HMAC!');
  const ciphertext = await aesCtrHmac.encrypt(plaintext, keys);
  const recovered = await aesCtrHmac.decrypt(ciphertext, keys);
  assert.deepEqual(recovered, plaintext);
});

test('aesCtrHmac: round-trip with binary data containing all 256 byte values', async () => {
  const keys = await generateTestKeys();
  const plaintext = new Uint8Array(256);
  for (let i = 0; i < 256; i++) plaintext[i] = i;
  const ciphertext = await aesCtrHmac.encrypt(plaintext, keys);
  const recovered = await aesCtrHmac.decrypt(ciphertext, keys);
  assert.deepEqual(recovered, plaintext);
});

test('aesCtrHmac: round-trip with empty data', async () => {
  const keys = await generateTestKeys();
  const plaintext = new Uint8Array(0);
  const ciphertext = await aesCtrHmac.encrypt(plaintext, keys);
  const recovered = await aesCtrHmac.decrypt(ciphertext, keys);
  assert.deepEqual(recovered, plaintext);
});

test('aesCtrHmac: round-trip with large data (1 MB)', async () => {
  const keys = await generateTestKeys();
  const plaintext = new Uint8Array(1024 * 1024);
  for (let offset = 0; offset < plaintext.length; offset += 65536) {
    globalThis.crypto.getRandomValues(
      plaintext.subarray(offset, offset + 65536),
    );
  }
  const ciphertext = await aesCtrHmac.encrypt(plaintext, keys);
  const recovered = await aesCtrHmac.decrypt(ciphertext, keys);
  assert.deepEqual(recovered, plaintext);
});

// ---------------------------------------------------------------------------
// Ciphertext properties
// ---------------------------------------------------------------------------

test('aesCtrHmac: ciphertext has correct overhead (counter + MAC)', async () => {
  const keys = await generateTestKeys();
  const plaintext = new TextEncoder().encode('overhead check');
  const ciphertext = await aesCtrHmac.encrypt(plaintext, keys);

  // 16-byte counter + plaintext length + 32-byte HMAC
  assert.equal(ciphertext.length, 16 + plaintext.length + 32);
});

test('aesCtrHmac: encrypting same data twice produces different ciphertext', async () => {
  const keys = await generateTestKeys();
  const plaintext = new TextEncoder().encode('deterministic?');
  const ct1 = await aesCtrHmac.encrypt(plaintext, keys);
  const ct2 = await aesCtrHmac.encrypt(plaintext, keys);

  // Different random counters => different ciphertext
  assert.notDeepEqual(ct1, ct2);

  // Both decrypt to the same plaintext
  assert.deepEqual(await aesCtrHmac.decrypt(ct1, keys), plaintext);
  assert.deepEqual(await aesCtrHmac.decrypt(ct2, keys), plaintext);
});

// ---------------------------------------------------------------------------
// Authentication and error cases
// ---------------------------------------------------------------------------

test('aesCtrHmac: decryption fails with wrong key', async () => {
  const keys1 = await generateTestKeys();
  const keys2 = await generateTestKeys();
  const plaintext = new TextEncoder().encode('secret');
  const ciphertext = await aesCtrHmac.encrypt(plaintext, keys1);
  await assert.rejects(
    () => aesCtrHmac.decrypt(ciphertext, keys2),
    /HMAC verification failed/,
  );
});

test('aesCtrHmac: decryption fails when ciphertext body is tampered', async () => {
  const keys = await generateTestKeys();
  const plaintext = new TextEncoder().encode('tamper the body');
  const ciphertext = await aesCtrHmac.encrypt(plaintext, keys);

  // Flip a byte in the ciphertext body (after 16-byte counter, before 32-byte MAC)
  const tampered = new Uint8Array(ciphertext);
  tampered[20] ^= 0xff;

  await assert.rejects(
    () => aesCtrHmac.decrypt(tampered, keys),
    /HMAC verification failed/,
  );
});

test('aesCtrHmac: decryption fails when MAC tag is tampered', async () => {
  const keys = await generateTestKeys();
  const plaintext = new TextEncoder().encode('tamper the mac');
  const ciphertext = await aesCtrHmac.encrypt(plaintext, keys);

  // Flip a byte in the last 32 bytes (the HMAC tag)
  const tampered = new Uint8Array(ciphertext);
  tampered[tampered.length - 1] ^= 0xff;

  await assert.rejects(
    () => aesCtrHmac.decrypt(tampered, keys),
    /HMAC verification failed/,
  );
});

test('aesCtrHmac: decryption fails when counter is tampered', async () => {
  const keys = await generateTestKeys();
  const plaintext = new TextEncoder().encode('tamper the counter');
  const ciphertext = await aesCtrHmac.encrypt(plaintext, keys);

  // Flip a byte in the counter (first 16 bytes)
  const tampered = new Uint8Array(ciphertext);
  tampered[0] ^= 0xff;

  await assert.rejects(
    () => aesCtrHmac.decrypt(tampered, keys),
    /HMAC verification failed/,
  );
});

test('aesCtrHmac: decryption fails with data too short', async () => {
  const keys = await generateTestKeys();

  // Less than counter (16) + MAC (32) = 48 bytes minimum
  const tooShort = new Uint8Array(30);

  await assert.rejects(
    () => aesCtrHmac.decrypt(tooShort, keys),
    /ciphertext too short/,
  );
});

test('aesCtrHmac: HMAC is verified before decryption attempt', async () => {
  // This test ensures the encrypt-then-MAC pattern is correctly implemented:
  // the HMAC check should reject before any decryption occurs.
  const keys = await generateTestKeys();
  const plaintext = new TextEncoder().encode('verify first');
  const ciphertext = await aesCtrHmac.encrypt(plaintext, keys);

  // Corrupt the ciphertext body AND the MAC. If HMAC is checked first, we
  // should get an HMAC error, not a decryption error.
  const tampered = new Uint8Array(ciphertext);
  tampered[20] ^= 0xff; // body
  tampered[tampered.length - 1] ^= 0xff; // MAC

  await assert.rejects(
    () => aesCtrHmac.decrypt(tampered, keys),
    /HMAC verification failed/,
  );
});
