export type AssertionEnvelope = { authenticatorData: Uint8Array; signature: Uint8Array }

export type AppAttestObject = {
  fmt: 'apple-appattest'
  attStmt: { x5c: Uint8Array[] }
  authData: Uint8Array
}
