import type { TurboModule } from 'react-native'

import { TurboModuleRegistry } from 'react-native'

/**
 * Each scope has its own registered key. Hashes and proofs are base64url; the
 * keyId is padded base64. Failures reject with a code; `E_INVALID_KEY` means
 * the OS no longer has the key.
 */
export interface Spec extends TurboModule {
  /** Android resolves false without the Play Store. */
  isSupported(): Promise<boolean>

  /**
   * Doesn't persist the keyId; `markAttested` does. Android binds
   * `clientDataHash` into the key's attestation certificate and deletes the
   * scope's unregistered keys.
   */
  generateKey(clientDataHash: string, scope: string): Promise<string>

  /** Android also deletes the scope's other keys. */
  markAttested(keyId: string, scope: string): Promise<void>

  /** Android also resolves null when the keyId was restored from a backup without its key. */
  getKeyId(scope: string): Promise<string | null>

  /** iOS can't delete the Secure Enclave key; Android deletes the Keystore key. */
  clearKeyId(scope: string): Promise<void>

  /**
   * `clientDataHash` is SHA-256(challenge). Resolves with the proof: Apple's
   * CBOR attestation object, or on Android JSON with the Play Integrity token
   * and the key's attestation certificate chain.
   */
  attestKey(keyId: string, clientDataHash: string): Promise<string>

  /** Resolves with Apple's CBOR assertion or, on Android, a DER ECDSA signature. */
  generateAssertion(keyId: string, clientDataHash: string): Promise<string>

  /** Hermes has no `crypto.subtle.digest`. */
  sha256(data: string): Promise<string>
}

const NativePeageAttest: Spec | null | undefined = TurboModuleRegistry.get<Spec>('PeageAttest')

export default NativePeageAttest
