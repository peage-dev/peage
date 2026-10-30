import type { SecurityLevel, VerifiedBootState } from '@peculiar/asn1-android'
import type { Name } from '@peculiar/asn1-x509'
import type { KeyObject, X509Certificate } from 'node:crypto'

/** A request as the client signs it; `bucket` defaults to the current one. */
export type RequestToSign = {
  method: string
  path: string
  body: Uint8Array
  bucket?: number
}

/** Stands in for Google's attestation roots. */
export type KeyAttestationTestRoot = {
  certificate: X509Certificate
  privateKey: KeyObject
  name: Name
}

/** What the device's key attestation says. Defaults describe a genuine, locked device. */
export type KeyDescriptionParams = {
  /** SHA-256 of the server challenge, as the client passes it to `generateKey`. */
  attestationChallenge: Uint8Array
  packageName: string
  attestationSecurityLevel?: SecurityLevel
  keySecurityLevel?: SecurityLevel
  origin?: number
  /** Leaves the origin out of the hardware-enforced list. */
  hardwareOmitsOrigin?: boolean
  deviceLocked?: boolean
  verifiedBootState?: VerifiedBootState
  /** Leaves the root of trust out of the hardware-enforced list. */
  hardwareOmitsRootOfTrust?: boolean
  /** SHA-256 digests of the generating app's signing certificates. */
  signingCertificateDigests?: Uint8Array[]
  /** Also lists a generated origin and a locked, verified boot as software-enforced. */
  softwareEnforcedClaimsGenuine?: boolean
  /** Lists the attestation application id as hardware-enforced instead of software-enforced. */
  applicationIdInHardwareOnly?: boolean
}

type IntermediateParams = {
  /** A serial number as its subject, as on factory-provisioned devices. */
  factoryProvisioned?: boolean
  expired?: boolean
  notYetValid?: boolean
  /** A key description above the leaf, as in a chain extended by an attacker. */
  withKeyDescription?: boolean
}

export type KeyAttestationChainParams = {
  root: KeyAttestationTestRoot
  publicKey: KeyObject
  /** `null` leaves it out of the leaf. */
  keyDescription: KeyDescriptionParams | null
  intermediate?: IntermediateParams
  leafExpired?: boolean
  /** The leaf is still signed by the intermediate's key. */
  leafNamesAnotherIssuer?: boolean
}

/** Stand-ins for the Play Console keys, plus Google's signing key. */
export type PlayIntegrityTestKeys = {
  /** Base64 AES-256 key, as downloaded from Play Console. */
  decryptionKey: string
  /** Base64 SPKI DER of the P-256 key that verifies verdicts. */
  verificationKey: string
  /** Google's side of `verificationKey`: signs the verdict JWS. */
  signingKey: KeyObject
}

/** Replace the protected headers, e.g. to test algorithm checks. */
export type PlayIntegrityTokenHeaders = { jwe?: object; jws?: object }

/** Google's classic verdict payload. App identity fields are absent when UNEVALUATED. */
export type PlayIntegrityVerdictPayload = {
  requestDetails: { requestPackageName: string; nonce: string; timestampMillis: string }
  appIntegrity: {
    appRecognitionVerdict: string
    packageName?: string
    certificateSha256Digest?: string[]
    versionCode?: string
  }
  deviceIntegrity: { deviceRecognitionVerdict?: string[] }
  accountDetails: { appLicensingVerdict: string }
}

export type PlayIntegrityVerdictParams = {
  packageName: string
  nonce: string
  timestampMillis?: number
  appRecognitionVerdict?: string
  deviceRecognitionVerdict?: string[]
  /** SHA-256 digests of the requesting app's signing certificates. */
  signingCertificateDigests?: Uint8Array[]
}
