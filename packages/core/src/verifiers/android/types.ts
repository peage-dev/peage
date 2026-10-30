import { type KeyObject, X509Certificate } from 'node:crypto'

import type { LoadRevokedSerialNumbers } from '../../types.ts'

export type PlayIntegrityProof = {
  integrityToken: string
  /** Base64 DER, leaf first, as the Keystore returns it. */
  certificateChain: string[]
}

export type PlayIntegrityVerdict = {
  requestDetails: {
    requestPackageName: string
    nonce: string
    timestampMillis: string
  }
  appIntegrity: {
    appRecognitionVerdict: string
    packageName?: string
    /** Base64url SHA-256 of each signing certificate of the app that requested the token. */
    certificateSha256Digest?: string[]
  }
  deviceIntegrity: {
    deviceRecognitionVerdict?: string[]
  }
}

export type ResolvedPlayIntegrityConfig = {
  packageName: string
  decryptionKey: Uint8Array
  verificationKey: KeyObject
  allowUnrecognizedApps: boolean
  keyAttestationRoots: X509Certificate[]
  revocationList: RevocationList
}

export type AttestationApplicationId = {
  packageNames: string[]
  signatureDigests: Uint8Array[]
}

export type AuthorizationList = {
  origin?: number
  rootOfTrust?: { deviceLocked: boolean; verifiedBootState: number }
  attestationApplicationId?: AttestationApplicationId
}

export type KeyDescription = {
  attestationSecurityLevel: number
  keySecurityLevel: number
  attestationChallenge: Uint8Array
  softwareEnforced: AuthorizationList
  hardwareEnforced: AuthorizationList
}

export type RevocationList = {
  load: LoadRevokedSerialNumbers
  latest: () => Promise<ReadonlySet<string> | undefined>
}
