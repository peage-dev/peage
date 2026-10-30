/** The version clients send in `X-Peage-Protocol-Version`. */
export const PROTOCOL_VERSION = '0.1.0'

/** Carries the device's keyId. */
export const HTTP_HEADER_KEY_ID = 'X-Peage-KeyId'
/** Carries the platform assertion, unpadded base64url. */
export const HTTP_HEADER_ASSERTION = 'X-Peage-Assertion'
/** Carries `PROTOCOL_VERSION`. */
export const HTTP_HEADER_PROTOCOL_VERSION = 'X-Peage-Protocol-Version'

const AUTHENTICATE_SCHEME = 'Peage'
const AUTHENTICATE_ERROR_PATTERN = new RegExp(`^${AUTHENTICATE_SCHEME}\\s+error="([a-z_]+)"$`)

/** The `error` values of a Péage `WWW-Authenticate` header. */
export type AuthenticateError =
  | 'unknown_key'
  | 'invalid_signature'
  | 'unknown_challenge'
  | 'invalid_attestation'

/** The `WWW-Authenticate` value of a 401: `Peage`, with `error="…"` when an error is given. */
export function formatAuthenticateHeader(error?: AuthenticateError): string {
  return error === undefined ? AUTHENTICATE_SCHEME : `${AUTHENTICATE_SCHEME} error="${error}"`
}

/** The `error` of a Péage `WWW-Authenticate` header, if there is one. */
export function parseAuthenticateError(header: string | null): string | undefined {
  const match = header?.match(AUTHENTICATE_ERROR_PATTERN)
  return match?.[1]
}

/** Issues a challenge. */
export const CHALLENGE_PATH = '/peage/challenge'
/** Registers an attested key. */
export const SOLVE_PATH = '/peage/solve'

/** iOS App Attest. */
export const PLATFORM_APP_ATTEST = 'app-attest' as const
/** Android Play Integrity with Key Attestation. */
export const PLATFORM_PLAY_INTEGRITY = 'play-integrity' as const

/** A platform identifier as it travels on the wire. */
export type Platform = typeof PLATFORM_APP_ATTEST | typeof PLATFORM_PLAY_INTEGRITY

/** Whether the value is a platform Péage supports. */
export function isPlatform(value: unknown): value is Platform {
  return value === PLATFORM_APP_ATTEST || value === PLATFORM_PLAY_INTEGRITY
}

const SIGNING_TAG = 'peage-request-v1'

/** The width of a signing time bucket. */
export const ASSERTION_BUCKET_SECONDS = 30

/** The start, in Unix seconds, of the time bucket holding `unixSeconds`. */
export function assertionBucket(unixSeconds: number): number {
  return Math.floor(unixSeconds / ASSERTION_BUCKET_SECONDS) * ASSERTION_BUCKET_SECONDS
}

/** The request fields a signature covers. */
export type CanonicalRequest = {
  /** From `assertionBucket`. */
  bucket: number
  method: string
  /** The request-target in origin-form. */
  path: string
  /** SHA-256 of the body after content coding is removed. */
  bodyDigest: Uint8Array
}

/** Throws a `TypeError` for a method not made of the letters A–Z or a path with CR or LF. */
export function assertCanonicalRequest(request: { method: string; path: string }): void {
  if (!/^[A-Z]+$/.test(request.method)) {
    throw new TypeError('Request method must be made of the letters A–Z')
  }
  if (/[\r\n]/.test(request.path)) {
    throw new TypeError('Request path must not contain CR or LF')
  }
}

/**
 * The bytes whose SHA-256 is the clientDataHash:
 * `peage-request-v1\n${bucket}\n${method}\n${path}\n` ‖ SHA-256(body).
 */
export function canonicalRequestBytes(request: CanonicalRequest): Uint8Array {
  const prefix = new TextEncoder().encode(
    `${SIGNING_TAG}\n${request.bucket}\n${request.method}\n${request.path}\n`,
  )
  return concatBytes(prefix, request.bodyDigest)
}

/** The parts joined into a new byte array. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0))
  let offset = 0
  for (const part of parts) {
    result.set(part, offset)
    offset += part.length
  }
  return result
}

/** True for any non-null, non-array object, including `Map` and `Uint8Array`. */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Padded standard base64. */
export function toBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

/** Unpadded base64url. */
export function toBase64url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Decodes base64 with or without padding, ignoring ASCII whitespace and unused
 * trailing bits. Throws a `DOMException` on anything else malformed.
 */
export function fromBase64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0))
}

/** Like `fromBase64`, but accepts `-` and `_` as well as `+` and `/`. */
export function fromBase64url(value: string): Uint8Array {
  return fromBase64(value.replace(/-/g, '+').replace(/_/g, '/'))
}
