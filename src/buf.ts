/**
 * TypeScript compatibility helper for Web Crypto API
 */
export function buf(data: Uint8Array): Uint8Array<ArrayBuffer> {
  return data as Uint8Array<ArrayBuffer>;
}
