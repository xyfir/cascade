/**
 * Best-effort secure memory wipe
 */
export function secureWipe(buffer: Uint8Array): void {
  buffer.fill(0);
}
