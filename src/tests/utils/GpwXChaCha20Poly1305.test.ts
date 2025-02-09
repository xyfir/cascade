import { GpwXChaCha20Poly1305 } from '../../utils/GpwXChaCha20Poly1305.js';
import { GpwPBKDF2 } from '../../utils/GpwPBKDF2.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';

test('GpwXChaCha20Poly1305', async () => {
  const plaintext = 'Hello, World!';
  const plaintextBuf = Buffer.from(plaintext, 'utf-8');

  const passkey = await GpwPBKDF2.deriveKey(
    'password',
    GpwPBKDF2.generateSalt(),
    GpwPBKDF2.generateIterations(true),
  ).then((p) => Buffer.from(p, 'base64'));

  const ciphertext = await GpwXChaCha20Poly1305.encrypt(
    plaintextBuf,
    passkey,
  ).then((c) => c.toString('base64'));
  const ciphertext2 = await GpwXChaCha20Poly1305.encrypt(
    plaintextBuf,
    passkey,
  ).then((c) => c.toString('base64'));

  const decrypted = await GpwXChaCha20Poly1305.decrypt(
    Buffer.from(ciphertext, 'base64'),
    passkey,
  ).then((d) => d.toString('utf-8'));

  assert.notEqual(ciphertext, ciphertext2);
  assert.notEqual(ciphertext, plaintext);
  assert.equal(decrypted, plaintext);
});
