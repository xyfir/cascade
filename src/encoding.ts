/**
 * Provides conversion helpers between text, binary, base64, and hex
 * representations. All functions use standard Web APIs (TextEncoder,
 * TextDecoder) and are fully isomorphic.
 */

export const encoding = {
  /** Encode a UTF-8 string to bytes. */
  textToBytes(text: string): Uint8Array {
    return new TextEncoder().encode(text);
  },

  /** Decode bytes to a UTF-8 string. */
  bytesToText(bytes: Uint8Array): string {
    return new TextDecoder().decode(bytes);
  },

  /** Encode bytes to a base64 string. */
  bytesToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]!);
    }
    return btoa(binary);
  },

  /** Decode a base64 string to bytes. */
  base64ToBytes(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  },

  /** Encode bytes to a lowercase hex string. */
  bytesToHex(bytes: Uint8Array): string {
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i]!.toString(16).padStart(2, '0');
    }
    return hex;
  },

  /** Decode a hex string to bytes. */
  hexToBytes(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) {
      throw new Error('Hex string must have even length');
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  },

  /**
   * Concatenate multiple Uint8Arrays into a single Uint8Array.
   *
   * Useful for combining encrypted blobs, IVs, and tags.
   */
  concatBytes(...arrays: Uint8Array[]): Uint8Array {
    let totalLength = 0;
    for (const arr of arrays) totalLength += arr.length;
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
      result.set(arr, offset);
      offset += arr.length;
    }
    return result;
  },
};
