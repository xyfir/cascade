import { GpwKeychain } from '../../types/index.js';
import { GpwPBKDF2 } from '../../utils/GpwPBKDF2.js';
import { GpwCrypto } from '../../utils/GpwCrypto.js';
import { nanoid } from 'nanoid';
import { test } from 'node:test';
import assert from 'node:assert/strict';

test('GpwCrypto with AES-256-GCM', async () => {
  const plaintext = 'Hello, World!';
  const passkey = await GpwPBKDF2.deriveKey(
    'password',
    GpwPBKDF2.generateSalt(),
    GpwPBKDF2.generateIterations(true),
  );
  const keychain: GpwKeychain = {
    keys: [
      {
        type: 'AES-256-GCM',
        data: passkey,
      },
    ],
    id: nanoid(),
  };

  const ciphertext = await GpwCrypto.encrypt(plaintext, keychain);
  const ciphertext2 = await GpwCrypto.encrypt(plaintext, keychain);
  const decrypted = await GpwCrypto.decrypt(ciphertext, keychain);

  assert.notEqual(ciphertext, ciphertext2);
  assert.notEqual(ciphertext, plaintext);
  assert.equal(decrypted, plaintext);
});

test('GpwCrypto with XChaCha20-Poly1305', async () => {
  const plaintext = 'Hello, World!';
  const passkey = await GpwPBKDF2.deriveKey(
    'password',
    GpwPBKDF2.generateSalt(),
    GpwPBKDF2.generateIterations(true),
  );
  const keychain: GpwKeychain = {
    keys: [
      {
        type: 'XChaCha20-Poly1305',
        data: passkey,
      },
    ],
    id: nanoid(),
  };

  const ciphertext = await GpwCrypto.encrypt(plaintext, keychain);
  const ciphertext2 = await GpwCrypto.encrypt(plaintext, keychain);
  const decrypted = await GpwCrypto.decrypt(ciphertext, keychain);

  assert.notEqual(ciphertext, ciphertext2);
  assert.notEqual(ciphertext, plaintext);
  assert.equal(decrypted, plaintext);
});

test('GpwCrypto with AES-256-GCM => XChaCha20-Poly1305', async () => {
  const plaintext = 'Hello, World!';
  const aesPasskey = await GpwPBKDF2.deriveKey(
    'password',
    GpwPBKDF2.generateSalt(),
    GpwPBKDF2.generateIterations(true),
  );
  const xchaPasskey = await GpwPBKDF2.deriveKey(
    'password2',
    GpwPBKDF2.generateSalt(),
    GpwPBKDF2.generateIterations(true),
  );

  const keychain: GpwKeychain = {
    keys: [
      {
        type: 'AES-256-GCM',
        data: aesPasskey,
      },
      {
        type: 'XChaCha20-Poly1305',
        data: xchaPasskey,
      },
    ],
    id: nanoid(),
  };

  const ciphertext = await GpwCrypto.encrypt(plaintext, keychain);
  const ciphertext2 = await GpwCrypto.encrypt(plaintext, keychain);
  const decrypted = await GpwCrypto.decrypt(ciphertext, keychain);

  assert.notEqual(ciphertext, ciphertext2);
  assert.notEqual(ciphertext, plaintext);
  assert.equal(decrypted, plaintext);
});

test('GpwCrypto with XChaCha20-Poly1305 => AES-256-GCM', async () => {
  const plaintext = 'Hello, World!';
  const aesPasskey = await GpwPBKDF2.deriveKey(
    'password',
    GpwPBKDF2.generateSalt(),
    GpwPBKDF2.generateIterations(true),
  );
  const xchaPasskey = await GpwPBKDF2.deriveKey(
    'password2',
    GpwPBKDF2.generateSalt(),
    GpwPBKDF2.generateIterations(true),
  );

  const keychain: GpwKeychain = {
    keys: [
      {
        type: 'XChaCha20-Poly1305',
        data: xchaPasskey,
      },
      {
        type: 'AES-256-GCM',
        data: aesPasskey,
      },
    ],
    id: nanoid(),
  };

  const ciphertext = await GpwCrypto.encrypt(plaintext, keychain);
  const ciphertext2 = await GpwCrypto.encrypt(plaintext, keychain);
  const decrypted = await GpwCrypto.decrypt(ciphertext, keychain);

  assert.notEqual(ciphertext, ciphertext2);
  assert.notEqual(ciphertext, plaintext);
  assert.equal(decrypted, plaintext);
});
