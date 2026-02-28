import test from 'node:test';
import assert from 'node:assert/strict';
import {
  argon2,
  ARGON2_OPSLIMIT_MIN,
  ARGON2_MEMLIMIT_MIN,
  ARGON2_SALT_LENGTH,
} from '../argon2.js';
import { getSodium } from '../sodium.js';

// Use minimum Argon2 parameters for fast tests
const TEST_OPS = ARGON2_OPSLIMIT_MIN;
const TEST_MEM = ARGON2_MEMLIMIT_MIN;

// ---------------------------------------------------------------------------
// Output properties
// ---------------------------------------------------------------------------

test('argon2: output key is 32 bytes', async () => {
  const { key } = await argon2({
    password: 'test',
    opsLimit: TEST_OPS,
    memLimit: TEST_MEM,
  });
  assert.equal(key.length, 32);
});

test('argon2: output is a Uint8Array', async () => {
  const { key } = await argon2({
    password: 'test',
    opsLimit: TEST_OPS,
    memLimit: TEST_MEM,
  });
  assert.ok(key instanceof Uint8Array);
});

// ---------------------------------------------------------------------------
// Salt generation
// ---------------------------------------------------------------------------

test('argon2: auto-generates 16-byte salt when omitted', async () => {
  const { salt } = await argon2({
    password: 'test',
    opsLimit: TEST_OPS,
    memLimit: TEST_MEM,
  });
  assert.equal(salt.length, ARGON2_SALT_LENGTH);
  assert.ok(salt instanceof Uint8Array);
});

test('argon2: auto-generated salts are random (two calls differ)', async () => {
  const result1 = await argon2({
    password: 'test',
    opsLimit: TEST_OPS,
    memLimit: TEST_MEM,
  });
  const result2 = await argon2({
    password: 'test',
    opsLimit: TEST_OPS,
    memLimit: TEST_MEM,
  });
  assert.notDeepEqual(result1.salt, result2.salt);
  assert.notDeepEqual(result1.key, result2.key);
});

test('argon2: uses provided salt when given', async () => {
  const sodium = await getSodium();
  const salt = sodium.randombytes_buf(ARGON2_SALT_LENGTH);
  const { salt: returnedSalt } = await argon2({
    password: 'test',
    salt,
    opsLimit: TEST_OPS,
    memLimit: TEST_MEM,
  });
  assert.deepEqual(returnedSalt, salt);
});

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

test('argon2: same password + salt + params => same key', async () => {
  const sodium = await getSodium();
  const salt = sodium.randombytes_buf(ARGON2_SALT_LENGTH);
  const result1 = await argon2({
    password: 'hunter2',
    salt,
    opsLimit: TEST_OPS,
    memLimit: TEST_MEM,
  });
  const result2 = await argon2({
    password: 'hunter2',
    salt,
    opsLimit: TEST_OPS,
    memLimit: TEST_MEM,
  });
  assert.deepEqual(result1.key, result2.key);
});

// ---------------------------------------------------------------------------
// Sensitivity to inputs
// ---------------------------------------------------------------------------

test('argon2: different passwords => different keys', async () => {
  const sodium = await getSodium();
  const salt = sodium.randombytes_buf(ARGON2_SALT_LENGTH);
  const result1 = await argon2({
    password: 'password-a',
    salt,
    opsLimit: TEST_OPS,
    memLimit: TEST_MEM,
  });
  const result2 = await argon2({
    password: 'password-b',
    salt,
    opsLimit: TEST_OPS,
    memLimit: TEST_MEM,
  });
  assert.notDeepEqual(result1.key, result2.key);
});

test('argon2: different salts => different keys', async () => {
  const sodium = await getSodium();
  const salt1 = sodium.randombytes_buf(ARGON2_SALT_LENGTH);
  const salt2 = sodium.randombytes_buf(ARGON2_SALT_LENGTH);
  const result1 = await argon2({
    password: 'same-password',
    salt: salt1,
    opsLimit: TEST_OPS,
    memLimit: TEST_MEM,
  });
  const result2 = await argon2({
    password: 'same-password',
    salt: salt2,
    opsLimit: TEST_OPS,
    memLimit: TEST_MEM,
  });
  assert.notDeepEqual(result1.key, result2.key);
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

test('argon2: handles empty password', async () => {
  const { key } = await argon2({
    password: '',
    opsLimit: TEST_OPS,
    memLimit: TEST_MEM,
  });
  assert.equal(key.length, 32);
});

test('argon2: handles Unicode password', async () => {
  const { key } = await argon2({
    password: '🔐 сложный пароль 密码',
    opsLimit: TEST_OPS,
    memLimit: TEST_MEM,
  });
  assert.equal(key.length, 32);
});

test('argon2: rejects salt with wrong length', async () => {
  await assert.rejects(
    () =>
      argon2({
        password: 'test',
        salt: new Uint8Array(8), // wrong length
        opsLimit: TEST_OPS,
        memLimit: TEST_MEM,
      }),
    /salt must be exactly 16 bytes/,
  );
});

test('argon2: rejects opsLimit below minimum', async () => {
  await assert.rejects(
    () =>
      argon2({
        password: 'test',
        opsLimit: 0,
        memLimit: TEST_MEM,
      }),
    /opsLimit must be at least/,
  );
});

test('argon2: rejects memLimit below minimum', async () => {
  await assert.rejects(
    () =>
      argon2({
        password: 'test',
        opsLimit: TEST_OPS,
        memLimit: 0,
      }),
    /memLimit must be at least/,
  );
});

test('argon2: accepts Uint8Array password', async () => {
  const password = new TextEncoder().encode('byte-password');
  const { key, salt } = await argon2({
    password,
    opsLimit: TEST_OPS,
    memLimit: TEST_MEM,
  });
  assert.equal(key.length, 32);
  assert.equal(salt.length, ARGON2_SALT_LENGTH);
});

test('argon2: Uint8Array password produces same key as equivalent string', async () => {
  const sodium = await getSodium();
  const salt = sodium.randombytes_buf(ARGON2_SALT_LENGTH);
  const passwordStr = 'same-password';
  const passwordBytes = new TextEncoder().encode(passwordStr);

  const result1 = await argon2({
    password: passwordStr,
    salt,
    opsLimit: TEST_OPS,
    memLimit: TEST_MEM,
  });
  const result2 = await argon2({
    password: passwordBytes,
    salt,
    opsLimit: TEST_OPS,
    memLimit: TEST_MEM,
  });
  assert.deepEqual(result1.key, result2.key);
});
