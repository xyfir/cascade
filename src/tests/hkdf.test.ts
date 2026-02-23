import test from 'node:test';
import assert from 'node:assert/strict';
import { hkdf } from '../hkdf.js';

// ---------------------------------------------------------------------------
// Output properties
// ---------------------------------------------------------------------------

test('hkdf: produces output of requested length (32 bytes)', async () => {
  const material = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const result = await hkdf(material, 'test-info', 32);
  assert.equal(result.length, 32);
  assert.ok(result instanceof Uint8Array);
});

test('hkdf: produces output of requested length (64 bytes)', async () => {
  const material = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const result = await hkdf(material, 'test-info', 64);
  assert.equal(result.length, 64);
});

test('hkdf: produces output of requested length (16 bytes)', async () => {
  const material = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const result = await hkdf(material, 'test-info', 16);
  assert.equal(result.length, 16);
});

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

test('hkdf: same material + info + length => same output', async () => {
  const material = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const result1 = await hkdf(material, 'deterministic', 32);
  const result2 = await hkdf(material, 'deterministic', 32);
  assert.deepEqual(result1, result2);
});

// ---------------------------------------------------------------------------
// Domain separation
// ---------------------------------------------------------------------------

test('hkdf: different info strings => different output', async () => {
  const material = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const result1 = await hkdf(material, 'purpose-a', 32);
  const result2 = await hkdf(material, 'purpose-b', 32);
  assert.notDeepEqual(result1, result2);
});

test('hkdf: layer isolation: layer-0 ≠ layer-1 from same material', async () => {
  const material = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const layer0 = await hkdf(material, 'cascade-password-layer-0', 32);
  const layer1 = await hkdf(material, 'cascade-password-layer-1', 32);
  assert.notDeepEqual(layer0, layer1);
});

test('hkdf: purpose isolation: password ≠ master ≠ content keys', async () => {
  const material = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const passwordKey = await hkdf(material, 'cascade-password-layer-0', 32);
  const masterKey = await hkdf(material, 'cascade-master-layer-0', 32);
  const contentKey = await hkdf(material, 'cascade-content-layer-0', 32);
  assert.notDeepEqual(passwordKey, masterKey);
  assert.notDeepEqual(masterKey, contentKey);
  assert.notDeepEqual(passwordKey, contentKey);
});

// ---------------------------------------------------------------------------
// Sensitivity to input material
// ---------------------------------------------------------------------------

test('hkdf: different input material => different output', async () => {
  const material1 = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const material2 = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const result1 = await hkdf(material1, 'same-info', 32);
  const result2 = await hkdf(material2, 'same-info', 32);
  assert.notDeepEqual(result1, result2);
});

// ---------------------------------------------------------------------------
// Varying output lengths from the same inputs
// ---------------------------------------------------------------------------

test('hkdf: 32-byte output is prefix of 64-byte output (HKDF expand property)', async () => {
  // HKDF-Expand produces output in blocks. The first 32 bytes of a 64-byte
  // derivation should be identical to a standalone 32-byte derivation,
  // because HKDF-Expand(PRK, info, 32) == first 32 bytes of
  // HKDF-Expand(PRK, info, 64) - both use T(1) = HMAC(PRK, info || 0x01)
  const material = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const short = await hkdf(material, 'prefix-test', 32);
  const long = await hkdf(material, 'prefix-test', 64);
  assert.deepEqual(short, long.slice(0, 32));
});
