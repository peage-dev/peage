import type { Platform } from '@peage/protocol'

import type { PeageError } from './errors.ts'

/** A challenge from `createChallenge`, as the store keeps it. */
export type IssuedChallenge = {
  /** 32 random bytes, unpadded base64url. */
  value: string
  platform: Platform
  /** Unix milliseconds. */
  expiresAt: number
}

/** A registered device key. */
export type AttestedKeyRecord = {
  keyId: string
  platform: Platform
  /** The app that registered the key: the App Attest appId or the Android package name. */
  appId: string
  /**
   * 'development' for a key accepted under a development setting: an Xcode
   * build on iOS, an unrecognized app on Android.
   */
  environment: AttestationEnvironment
  /** Base64 SPKI DER. */
  publicKey: string
  /** Unix milliseconds. */
  attestedAt: number
  /** Android only: serial numbers of the key's attestation certificates. */
  attestationCertificateSerialNumbers?: string[]
}

/** Persists issued challenges and attested keys. */
export type PeageStore = {
  /** Saves an issued challenge. It only needs to be kept until `expiresAt`. */
  saveChallenge(challenge: IssuedChallenge): Promise<void>

  /**
   * Removes and returns a challenge atomically (e.g. Redis `GETDEL`). Returns
   * null if it was never issued or was already taken.
   */
  takeChallenge(challenge: { value: string; platform: Platform }): Promise<IssuedChallenge | null>

  /** Saves a key record, replacing any record with the same keyId. */
  saveAttestedKey(record: AttestedKeyRecord): Promise<void>

  /**
   * Returns the record for `keyId`, or null. Must return a record as soon as
   * `saveAttestedKey` has resolved, e.g. not from a lagging replica.
   */
  loadAttestedKey(key: { keyId: string }): Promise<AttestedKeyRecord | null>
}

/** A platform-specific attestation that proves the client controls a device key. */
export type RegistrationRequest = {
  platform: Platform
  /** A challenge from `createChallenge`. */
  challenge: string
  /** Padded base64 of the SHA-256 of the key's uncompressed P-256 point, in canonical spelling. */
  keyId: string
  /**
   * - App Attest: the CBOR attestation object `attestKey` returned.
   * - Play Integrity: UTF-8 JSON `{ integrityToken, certificateChain }`.
   */
  proof: Uint8Array
}

/** A protected request as the adapter received it. */
export type SignedRequest = {
  /** From the `X-Peage-KeyId` header. */
  keyId: string
  /** Uppercase, as the client signed it. */
  method: string
  /**
   * The request-target in origin-form (path and query, byte for byte); an
   * absolute-form target is reduced to it first.
   */
  path: string
  /**
   * - App Attest: the CBOR assertion `generateAssertion` returned.
   * - Play Integrity: a DER ECDSA signature.
   */
  assertion: Uint8Array
  /**
   * Returns the body with transfer and content coding removed. Called only once
   * the key is found registered and usable.
   */
  readBody: () => Promise<Uint8Array>
}

/** A signed request whose signature matched its registered key. */
export type VerifiedRequest = {
  keyId: string
  platform: Platform
  /** The body the signature covers, after content decoding. */
  body: Uint8Array
}

/** `'development'` covers Xcode builds on iOS and apps Play doesn't recognize on Android. */
export type AttestationEnvironment = 'production' | 'development'

/** Enables iOS App Attest. */
export type AppAttestConfig = {
  /** `<Team ID>.<bundle identifier>`, e.g. `ABCDE12345.com.example.app`. */
  appId: string

  /**
   * By default only production attestations (TestFlight, App Store) are
   * accepted. 'development' accepts development ones instead (Xcode builds).
   */
  environment?: AttestationEnvironment
}

/**
 * Enables Android. The server downloads Google's attestation revocation list
 * from `https://android.googleapis.com/attestation/status` (about 200 KB, about
 * once a day): allow that outbound HTTPS call, or provide
 * `keyAttestation.loadRevokedSerialNumbers`.
 */
export type PlayIntegrityConfig = {
  /** The Android application ID, e.g. `com.example.app`. */
  packageName: string
  /** Base64 AES-256 key from Play Console's self-managed response encryption keys. */
  decryptionKey: string
  /** Base64 SPKI DER of the EC P-256 key from the same Play Console download. */
  verificationKey: string

  /**
   * Also accept UNRECOGNIZED_VERSION: a debug build installed with adb, but
   * also any re-signed or repackaged APK. Never enable in production.
   */
  allowUnrecognizedApps?: boolean

  keyAttestation?: KeyAttestationConfig
}

/**
 * Resolves the serial numbers of revoked attestation certificates, in
 * lowercase hex without leading zeros. Called on every registration and
 * Android signed request: return a cached list.
 */
export type LoadRevokedSerialNumbers = () => Promise<ReadonlySet<string>>

/** Android Key Attestation settings; the defaults use Google's roots and revocation list. */
export type KeyAttestationConfig = {
  /** PEM. Defaults to Google's roots, bundled with Péage; replace only in tests. */
  trustedRoots?: string[]

  /** Defaults to Google's list. */
  loadRevokedSerialNumbers?: LoadRevokedSerialNumbers
}

/**
 * - `REQUEST_MALFORMED`: missing fields, or not in canonical form.
 * - `PLATFORM_DISABLED`: the server doesn't have this platform configured.
 * - `CHALLENGE_UNKNOWN`: the challenge was never issued, already used, or expired.
 * - `ATTESTATION_INVALID`: the attestation failed verification.
 * - `KEY_UNKNOWN`: no usable key is registered under this keyId.
 * - `SIGNATURE_INVALID`: the signature doesn't match the request and the stored key.
 *
 * Errors that aren't a `PeageError` are server failures, e.g. the store being down.
 */
export type PeageErrorCode =
  | 'REQUEST_MALFORMED'
  | 'PLATFORM_DISABLED'
  | 'CHALLENGE_UNKNOWN'
  | 'ATTESTATION_INVALID'
  | 'KEY_UNKNOWN'
  | 'SIGNATURE_INVALID'

/**
 * Reported to `onEvent` when core accepts a registration or signed request, or
 * rejects it with a `PeageError`. `request.verified` means the signature
 * verified; the adapter may still reject the request, e.g. `@peage/express`
 * answers 400 to a JSON body that doesn't parse.
 */
export type PeageEvent =
  | { type: 'registration.accepted'; keyId: string; platform: Platform }
  | { type: 'registration.rejected'; keyId: string; platform: Platform; error: PeageError }
  | { type: 'request.verified'; keyId: string; platform: Platform }
  | { type: 'request.rejected'; keyId: string; error: PeageError }

/** At least one platform must be configured; requests for the other are rejected. */
export type PeageConfig = {
  /** Where issued challenges and attested keys are persisted. */
  store: PeageStore
  /** Errors the hook throws or rejects with are ignored. */
  onEvent?: (event: PeageEvent) => void
} & (
  | { appAttest: AppAttestConfig; playIntegrity?: PlayIntegrityConfig | undefined }
  | { appAttest?: AppAttestConfig | undefined; playIntegrity: PlayIntegrityConfig }
)

/** Every method rejects with a `PeageError` when it refuses a request. */
export type Peage = {
  /** Whether the server has the platform configured. */
  isPlatformEnabled(platform: Platform): boolean

  /** Issues a single-use challenge that a device attests a new key against. */
  createChallenge(platform: Platform): Promise<string>

  /** Consumes the challenge, verifies the attestation and stores the attested key. */
  solveChallenge(request: RegistrationRequest): Promise<AttestedKeyRecord>

  /** Verifies a signed request against the stored key and returns its body. */
  verifyAssertion(request: SignedRequest): Promise<VerifiedRequest>
}
