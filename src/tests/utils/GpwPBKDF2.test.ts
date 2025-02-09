import { GpwPBKDF2 } from '../../utils/GpwPBKDF2.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';

test('GpwPBKDF2.generateIterations()', () => {
  const iterations = GpwPBKDF2.generateIterations();
  assert.ok(iterations >= 1000000, 'Iterations should be >= 1000000');
});

test('GpwPBKDF2.generateSalt()', () => {
  const salt = GpwPBKDF2.generateSalt();
  assert.equal(salt.length, 24, 'Salt should be 24 characters long');
});

test('GpwPBKDF2.deriveKey(pass, salt, itr)', async () => {
  const pass = 'password';
  const salt = GpwPBKDF2.generateSalt();
  const itr = GpwPBKDF2.generateIterations(true);
  const key = await GpwPBKDF2.deriveKey(pass, salt, itr);

  assert.match(key, /^[-A-Za-z0-9+/=]{44}$/, 'Key should be base64 encoded');

  const sameKey = await GpwPBKDF2.deriveKey(pass, salt, itr);
  assert.equal(key, sameKey, 'Same inputs should produce same key');
});
