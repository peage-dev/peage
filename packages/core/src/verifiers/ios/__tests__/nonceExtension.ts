/**
 * Wrap a nonce in the DER structure Apple uses for the App Attest nonce
 * extension: SEQUENCE { [1] EXPLICIT { OCTET STRING nonce } }.
 */
export function generateDerNonce(nonce: Uint8Array): Uint8Array {
  const octetString = [0x04, nonce.length, ...nonce]
  const contextTag = [0xa1, octetString.length, ...octetString]
  return new Uint8Array([0x30, contextTag.length, ...contextTag])
}
