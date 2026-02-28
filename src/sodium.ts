/**
 * Libsodium initialization helper.
 *
 * Ensures the libsodium WASM module is loaded exactly once before use.
 * All modules that depend on libsodium should call `getSodium()` to
 * obtain the initialized sodium instance.
 */

import _sodium from 'libsodium-wrappers-sumo';

let _ready: Promise<typeof _sodium> | null = null;

/**
 * Get the initialized libsodium instance.
 *
 * The first call triggers WASM module loading. Subsequent calls return
 * the cached instance immediately.
 */
export function getSodium(): Promise<typeof _sodium> {
  if (!_ready) {
    _ready = _sodium.ready.then(() => _sodium);
  }
  return _ready;
}
