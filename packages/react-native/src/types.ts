/** Mirrors the Codegen spec in `NativePeageAttest.ts` without importing React Native. */
export type NativeAttest = {
  isSupported(): Promise<boolean>
  generateKey(clientDataHash: string, scope: string): Promise<string>
  markAttested(keyId: string, scope: string): Promise<void>
  getKeyId(scope: string): Promise<string | null>
  clearKeyId(scope: string): Promise<void>
  attestKey(keyId: string, clientDataHash: string): Promise<string>
  generateAssertion(keyId: string, clientDataHash: string): Promise<string>
  sha256(data: string): Promise<string>
}

/**
 * - `UNSUPPORTED`: the device can't attest keys (no App Attest, or no Play Store).
 * - `NETWORK`: the server couldn't be reached.
 * - `CHALLENGE_FAILED`: the challenge expired before registration finished.
 * - `ATTESTATION_REJECTED`: the server refused the device's attestation (401).
 * - `SERVER`: the server failed or answered unexpectedly; worth retrying later.
 * - `NATIVE`: the platform module failed; `cause.code` is its error code. On Android,
 *   when Play Integrity fails with an `IntegrityErrorCode`, `cause.userInfo.integrityErrorCode`
 *   carries it.
 * - `REGISTRATION_STOPPED`: registration failed `maxRegistrationAttempts` times
 *   in a row; `cause` carries the last failure. Call `clearKey()` to try again.
 */
export type PeageClientErrorCode =
  | 'UNSUPPORTED'
  | 'NETWORK'
  | 'CHALLENGE_FAILED'
  | 'ATTESTATION_REJECTED'
  | 'SERVER'
  | 'NATIVE'
  | 'REGISTRATION_STOPPED'

/** Options for `createPeageClient`. */
export type PeageClientOptions = {
  /**
   * An `http://` or `https://` URL whose path, if any, starts with `/`, e.g.
   * `https://api.example.com/v1`; its path is put in front of the paths passed to `fetch`.
   * Registration POSTs to `${baseUrl}/peage/challenge` and `${baseUrl}/peage/solve`.
   */
  baseUrl: string
  /** Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch
  /**
   * Names the device key: clients with the same scope share one key, its
   * registration and its failed-registration count. Defaults to `baseUrl`,
   * normalized.
   */
  keyScope?: string
  /**
   * Consecutive failed registrations after which the client fails with
   * REGISTRATION_STOPPED, until `clearKey()` or a restart. NETWORK and
   * UNSUPPORTED failures don't count. Defaults to 3.
   */
  maxRegistrationAttempts?: number
}

/** Signs requests with this device's attested key, registering the key with the server when needed. */
export type PeageClient = {
  /** Whether this device can attest keys: App Attest on iOS, the Play Store on Android. */
  isSupported(): Promise<boolean>
  /** Registers this device's key once; later calls return the stored keyId. */
  register(): Promise<string>
  /**
   * A drop-in `fetch` that signs requests. `input` is a path starting with `/`, appended to
   * `baseUrl`'s path; a URL on `baseUrl`'s origin; or a `Request`, whose body is sent as bytes.
   * The method is uppercased. Bodies must be a string or a `Uint8Array`. Forwards `headers`,
   * `signal` and `credentials`; ignores other options. Throws a `TypeError` for `cache`, a
   * body on GET or HEAD, a `Content-Encoding` other than `identity` or lowercase `gzip`,
   * `gzip` on a non-string body, and a string body whose charset isn't UTF-8.
   * Registers when needed, and again if the server no longer knows the key.
   */
  fetch(input: string | URL | Request, init?: RequestInit): Promise<Response>
  /** The next request registers a new key. Not a logout: the server still trusts the old key. */
  clearKey(): Promise<void>
}

export type FailedRegistrations = {
  readonly count: number
  readonly lastError: unknown
}

export type ServerLocation = {
  origin: string
  basePath: string
}

export type RequestToSend = {
  method: string
  path: string
  body: string | Uint8Array | undefined
  headers: Headers
  signal: AbortSignal | undefined
  credentials: RequestInit['credentials']
}
