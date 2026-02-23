import test from 'node:test';
import assert from 'node:assert/strict';
import { pbkdf2 } from '../pbkdf2.js';

// Use low iterations for fast tests
const TEST_ITERATIONS = 1000;

// ---------------------------------------------------------------------------
// Output properties
// ---------------------------------------------------------------------------

test('pbkdf2: output key is 32 bytes', async () => {
  const { key } = await pbkdf2({
    password: 'test',
    iterations: TEST_ITERATIONS,
  });
  assert.equal(key.length, 32);
});

test('pbkdf2: output is a Uint8Array', async () => {
  const { key } = await pbkdf2({
    password: 'test',
    iterations: TEST_ITERATIONS,
  });
  assert.ok(key instanceof Uint8Array);
});

// ---------------------------------------------------------------------------
// Salt generation
// ---------------------------------------------------------------------------

test('pbkdf2: auto-generates 32-byte salt when omitted', async () => {
  const { salt } = await pbkdf2({
    password: 'test',
    iterations: TEST_ITERATIONS,
  });
  assert.equal(salt.length, 32);
  assert.ok(salt instanceof Uint8Array);
});

test('pbkdf2: auto-generated salts are random (two calls differ)', async () => {
  const result1 = await pbkdf2({
    password: 'test',
    iterations: TEST_ITERATIONS,
  });
  const result2 = await pbkdf2({
    password: 'test',
    iterations: TEST_ITERATIONS,
  });
  assert.notDeepEqual(result1.salt, result2.salt);
  assert.notDeepEqual(result1.key, result2.key);
});

test('pbkdf2: uses provided salt when given', async () => {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const { salt: returnedSalt } = await pbkdf2({
    password: 'test',
    salt,
    iterations: TEST_ITERATIONS,
  });
  assert.deepEqual(returnedSalt, salt);
});

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

test('pbkdf2: same password + salt + iterations => same key', async () => {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const result1 = await pbkdf2({
    password: 'hunter2',
    salt,
    iterations: TEST_ITERATIONS,
  });
  const result2 = await pbkdf2({
    password: 'hunter2',
    salt,
    iterations: TEST_ITERATIONS,
  });
  assert.deepEqual(result1.key, result2.key);
});

// ---------------------------------------------------------------------------
// Sensitivity to inputs
// ---------------------------------------------------------------------------

test('pbkdf2: different passwords => different keys', async () => {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const result1 = await pbkdf2({
    password: 'password-a',
    salt,
    iterations: TEST_ITERATIONS,
  });
  const result2 = await pbkdf2({
    password: 'password-b',
    salt,
    iterations: TEST_ITERATIONS,
  });
  assert.notDeepEqual(result1.key, result2.key);
});

test('pbkdf2: different salts => different keys', async () => {
  const salt1 = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const salt2 = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const result1 = await pbkdf2({
    password: 'same-password',
    salt: salt1,
    iterations: TEST_ITERATIONS,
  });
  const result2 = await pbkdf2({
    password: 'same-password',
    salt: salt2,
    iterations: TEST_ITERATIONS,
  });
  assert.notDeepEqual(result1.key, result2.key);
});

test('pbkdf2: different iterations => different keys', async () => {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const result1 = await pbkdf2({
    password: 'same-password',
    salt,
    iterations: 1000,
  });
  const result2 = await pbkdf2({
    password: 'same-password',
    salt,
    iterations: 2000,
  });
  assert.notDeepEqual(result1.key, result2.key);
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

test('pbkdf2: handles empty password', async () => {
  const { key } = await pbkdf2({
    password: '',
    iterations: TEST_ITERATIONS,
  });
  assert.equal(key.length, 32);
});

test('pbkdf2: handles Unicode password', async () => {
  const { key } = await pbkdf2({
    password: '🔐 сложный пароль 密码',
    iterations: TEST_ITERATIONS,
  });
  assert.equal(key.length, 32);
});

test('pbkdf2: handles minimum salt (1 byte)', async () => {
  const salt = new Uint8Array([0x42]);
  const { key } = await pbkdf2({
    password: 'test',
    salt,
    iterations: TEST_ITERATIONS,
  });
  assert.equal(key.length, 32);
});
