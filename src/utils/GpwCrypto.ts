import { GpwXChaCha20Poly1305 } from './GpwXChaCha20Poly1305.js';
import { GpwAES } from './GpwAES.js';
import type {
  GpwUnlockedKeychain,
  GpwEncryptedString,
} from '../types/index.js';

/**
 * A high-level wrapper for encrypting and decrypting text strings using
 *  Gpw keychains.
 */
export class GpwCrypto {
  /**
   * Encrypts plaintext with provided keychain
   */
  public static async encrypt(
    plaintext: string,
    keychain: GpwUnlockedKeychain,
  ): Promise<GpwEncryptedString> {
    let data = Buffer.from(plaintext, 'utf-8');

    for (const key of keychain.keys) {
      const k = Buffer.from(key.data, 'base64');

      switch (key.type) {
        case 'XChaCha20-Poly1305':
          data = (await GpwXChaCha20Poly1305.encrypt(
            data,
            k,
          )) as Buffer<ArrayBuffer>;
          break;
        case 'AES-256-GCM':
          data = (await GpwAES.encrypt(data, k)) as Buffer<ArrayBuffer>;
          break;
        default:
          throw Error('Invalid encryption type');
      }
    }

    return data.toString('base64');
  }

  /**
   * Decrypts ciphertext with provided keys
   */
  public static async decrypt(
    ciphertext: GpwEncryptedString,
    keychain: GpwUnlockedKeychain,
  ): Promise<string> {
    let data = Buffer.from(ciphertext, 'base64');
    const keys = keychain.keys.slice().reverse();

    for (const key of keys) {
      const k = Buffer.from(key.data, 'base64');

      switch (key.type) {
        case 'XChaCha20-Poly1305':
          data = (await GpwXChaCha20Poly1305.decrypt(
            data,
            k,
          )) as Buffer<ArrayBuffer>;
          break;
        case 'AES-256-GCM':
          data = (await GpwAES.decrypt(data, k)) as Buffer<ArrayBuffer>;
          break;
        default:
          throw Error('Invalid encryption type');
      }
    }

    return data.toString('utf-8');
  }
}
