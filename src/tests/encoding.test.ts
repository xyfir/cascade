import test from 'node:test';
import assert from 'node:assert/strict';
import { encoding } from '../encoding.js';
import { secureWipe } from '../secureWipe.js';

// ---------------------------------------------------------------------------
// Text encoding (UTF-8)
// ---------------------------------------------------------------------------

test('encoding: textToBytes and bytesToText round-trip ASCII', () => {
  const text = 'Hello, World!';
  const bytes = encoding.textToBytes(text);
  assert.equal(encoding.bytesToText(bytes), text);
});

test('encoding: textToBytes and bytesToText round-trip Unicode', () => {
  const text = 'Привет, мир! 你好世界 🌍🔑';
  const bytes = encoding.textToBytes(text);
  assert.equal(encoding.bytesToText(bytes), text);
});

test('encoding: textToBytes and bytesToText round-trip empty string', () => {
  const bytes = encoding.textToBytes('');
  assert.equal(bytes.length, 0);
  assert.equal(encoding.bytesToText(bytes), '');
});

test('encoding: textToBytes produces correct UTF-8 bytes', () => {
  // 'A' = 0x41
  const bytes = encoding.textToBytes('A');
  assert.equal(bytes.length, 1);
  assert.equal(bytes[0], 0x41);
});

// ---------------------------------------------------------------------------
// Base64 encoding
// ---------------------------------------------------------------------------

test('encoding: bytesToBase64 and base64ToBytes round-trip', () => {
  const original = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
  const base64 = encoding.bytesToBase64(original);
  assert.equal(base64, 'SGVsbG8=');
  const recovered = encoding.base64ToBytes(base64);
  assert.deepEqual(recovered, original);
});

test('encoding: base64 round-trip with all 256 byte values', () => {
  const original = new Uint8Array(256);
  for (let i = 0; i < 256; i++) original[i] = i;
  const base64 = encoding.bytesToBase64(original);
  const recovered = encoding.base64ToBytes(base64);
  assert.deepEqual(recovered, original);
});

test('encoding: base64 round-trip with empty input', () => {
  const base64 = encoding.bytesToBase64(new Uint8Array(0));
  assert.equal(base64, '');
  const recovered = encoding.base64ToBytes(base64);
  assert.equal(recovered.length, 0);
});

test('encoding: base64 round-trip with random binary data', () => {
  const original = globalThis.crypto.getRandomValues(new Uint8Array(1000));
  const base64 = encoding.bytesToBase64(original);
  const recovered = encoding.base64ToBytes(base64);
  assert.deepEqual(recovered, original);
});

// ---------------------------------------------------------------------------
// Hex encoding
// ---------------------------------------------------------------------------

test('encoding: bytesToHex and hexToBytes round-trip', () => {
  const original = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
  const hex = encoding.bytesToHex(original);
  assert.equal(hex, 'deadbeef');
  const recovered = encoding.hexToBytes(hex);
  assert.deepEqual(recovered, original);
});

test('encoding: hex round-trip with all 256 byte values', () => {
  const original = new Uint8Array(256);
  for (let i = 0; i < 256; i++) original[i] = i;
  const hex = encoding.bytesToHex(original);
  assert.equal(hex.length, 512); // 2 hex chars per byte
  const recovered = encoding.hexToBytes(hex);
  assert.deepEqual(recovered, original);
});

test('encoding: hex round-trip with empty input', () => {
  const hex = encoding.bytesToHex(new Uint8Array(0));
  assert.equal(hex, '');
  const recovered = encoding.hexToBytes(hex);
  assert.equal(recovered.length, 0);
});

test('encoding: hex pads single-digit values with leading zero', () => {
  const bytes = new Uint8Array([0x00, 0x01, 0x0f]);
  const hex = encoding.bytesToHex(bytes);
  assert.equal(hex, '00010f');
});

test('encoding: hexToBytes throws on odd-length string', () => {
  assert.throws(() => encoding.hexToBytes('abc'), /even length/);
});

// ---------------------------------------------------------------------------
// concatBytes
// ---------------------------------------------------------------------------

test('encoding: concatBytes joins multiple arrays', () => {
  const a = new Uint8Array([1, 2]);
  const b = new Uint8Array([3, 4, 5]);
  const c = new Uint8Array([6]);
  const result = encoding.concatBytes(a, b, c);
  assert.deepEqual(result, new Uint8Array([1, 2, 3, 4, 5, 6]));
});

test('encoding: concatBytes with empty arrays', () => {
  const a = new Uint8Array(0);
  const b = new Uint8Array([1, 2]);
  const c = new Uint8Array(0);
  const result = encoding.concatBytes(a, b, c);
  assert.deepEqual(result, new Uint8Array([1, 2]));
});

test('encoding: concatBytes with no arguments returns empty array', () => {
  const result = encoding.concatBytes();
  assert.equal(result.length, 0);
});

test('encoding: concatBytes with single argument returns copy', () => {
  const original = new Uint8Array([1, 2, 3]);
  const result = encoding.concatBytes(original);
  assert.deepEqual(result, original);

  // Verify it's a copy, not the same reference
  result[0] = 99;
  assert.equal(original[0], 1);
});

// ---------------------------------------------------------------------------
// secureWipe
// ---------------------------------------------------------------------------

test('secureWipe: zeroes a buffer', () => {
  const buffer = new Uint8Array([1, 2, 3, 4, 5]);
  secureWipe(buffer);
  assert.deepEqual(buffer, new Uint8Array(5)); // all zeros
});

test('secureWipe: handles empty buffer', () => {
  const buffer = new Uint8Array(0);
  secureWipe(buffer); // should not throw
  assert.equal(buffer.length, 0);
});

test('secureWipe: zeroes a large buffer', () => {
  const buffer = globalThis.crypto.getRandomValues(new Uint8Array(10_000));

  // Verify it's not already all zeros
  let hasNonZero = false;
  for (let i = 0; i < buffer.length; i++) {
    if (buffer[i] !== 0) {
      hasNonZero = true;
      break;
    }
  }
  assert.ok(hasNonZero, 'Random buffer should have non-zero bytes');

  secureWipe(buffer);

  for (let i = 0; i < buffer.length; i++) {
    assert.equal(buffer[i], 0, `Byte at index ${i} should be zero`);
  }
});
