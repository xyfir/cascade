import test from 'node:test';
import assert from 'node:assert/strict';
import {
  kdf,
  KDF_CONTEXT_PASSWORD,
  KDF_CONTEXT_MASTER,
  KDF_CONTEXT_CONTENT,
} from '../kdf.js';
import { getSodium } from '../sodium.js';

// ---------------------------------------------------------------------------
// Output properties
// ---------------------------------------------------------------------------

test('kdf: produces output of requested length (32 bytes)', async () => {
  const sodium = await getSodium();
  const key = sodium.randombytes_buf(32);
  const result = await kdf(key, KDF_CONTEXT_PASSWORD, 0, 32);
  assert.equal(result.length, 32);
  assert.ok(result instanceof Uint8Array);
});

test('kdf: produces output of requested length (16 bytes)', async () => {
  const sodium = await getSodium();
  const key = sodium.randombytes_buf(32);
  const result = await kdf(key, KDF_CONTEXT_PASSWORD, 0, 16);
  assert.equal(result.length, 16);
});

test('kdf: produces output of requested length (64 bytes)', async () => {
  const sodium = await getSodium();
  const key = sodium.randombytes_buf(32);
  const result = await kdf(key, KDF_CONTEXT_PASSWORD, 0, 64);
  assert.equal(result.length, 64);
});

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

test('kdf: same key + context + subkeyId + length => same output', async () => {
  const sodium = await getSodium();
  const key = sodium.randombytes_buf(32);
  const result1 = await kdf(key, KDF_CONTEXT_PASSWORD, 0, 32);
  const result2 = await kdf(key, KDF_CONTEXT_PASSWORD, 0, 32);
  assert.deepEqual(result1, result2);
});

// ---------------------------------------------------------------------------
// Domain separation
// ---------------------------------------------------------------------------

test('kdf: different context strings => different output', async () => {
  const sodium = await getSodium();
  const key = sodium.randombytes_buf(32);
  const result1 = await kdf(key, KDF_CONTEXT_PASSWORD, 0, 32);
  const result2 = await kdf(key, KDF_CONTEXT_MASTER, 0, 32);
  assert.notDeepEqual(result1, result2);
});

test('kdf: different subkey IDs => different output', async () => {
  const sodium = await getSodium();
  const key = sodium.randombytes_buf(32);
  const result1 = await kdf(key, KDF_CONTEXT_PASSWORD, 0, 32);
  const result2 = await kdf(key, KDF_CONTEXT_PASSWORD, 1, 32);
  assert.notDeepEqual(result1, result2);
});

test('kdf: layer isolation: layer-0 != layer-1 from same material', async () => {
  const sodium = await getSodium();
  const key = sodium.randombytes_buf(32);
  const layer0 = await kdf(key, KDF_CONTEXT_PASSWORD, 0, 32);
  const layer1 = await kdf(key, KDF_CONTEXT_PASSWORD, 1, 32);
  assert.notDeepEqual(layer0, layer1);
});

test('kdf: purpose isolation: password != master != content keys', async () => {
  const sodium = await getSodium();
  const key = sodium.randombytes_buf(32);
  const passwordKey = await kdf(key, KDF_CONTEXT_PASSWORD, 0, 32);
  const masterKey = await kdf(key, KDF_CONTEXT_MASTER, 0, 32);
  const contentKey = await kdf(key, KDF_CONTEXT_CONTENT, 0, 32);
  assert.notDeepEqual(passwordKey, masterKey);
  assert.notDeepEqual(masterKey, contentKey);
  assert.notDeepEqual(passwordKey, contentKey);
});

// ---------------------------------------------------------------------------
// Sensitivity to input material
// ---------------------------------------------------------------------------

test('kdf: different input keys => different output', async () => {
  const sodium = await getSodium();
  const key1 = sodium.randombytes_buf(32);
  const key2 = sodium.randombytes_buf(32);
  const result1 = await kdf(key1, KDF_CONTEXT_PASSWORD, 0, 32);
  const result2 = await kdf(key2, KDF_CONTEXT_PASSWORD, 0, 32);
  assert.notDeepEqual(result1, result2);
});

// ---------------------------------------------------------------------------
// Context constants
// ---------------------------------------------------------------------------

test('kdf: context constants are 8 characters', () => {
  assert.equal(KDF_CONTEXT_PASSWORD.length, 8);
  assert.equal(KDF_CONTEXT_MASTER.length, 8);
  assert.equal(KDF_CONTEXT_CONTENT.length, 8);
});
