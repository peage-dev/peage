import { isRecord } from '@peage/protocol'

import type { FailedRegistrations, NativeAttest } from './types.ts'

import { PeageClientError } from './errors.ts'
import {
  authenticateErrorOf,
  declaredCharsets,
  isSupportedContentEncoding,
  isUtf8,
} from './headers.ts'
import { callNative } from './native.ts'

export function assertValidBaseUrl(origin: string, path: string): void {
  if (!/^https?:\/\//i.test(origin) || !(path === '' || path.startsWith('/'))) {
    throw new TypeError(
      'Péage baseUrl must be an `http://` or `https://` URL whose path, if any, starts with /',
    )
  }
}

export function assertSameOrigin(targetOrigin: string, serverOrigin: string): void {
  if (targetOrigin !== serverOrigin) {
    throw new TypeError(`Péage only signs requests to ${serverOrigin}`)
  }
}

export function assertAbsolutePath(path: string): void {
  if (!path.startsWith('/')) {
    throw new TypeError('Péage paths must start with /')
  }
}

export function assertSupportedOptions(init: RequestInit): void {
  if ('cache' in init && init.cache !== undefined) {
    throw new TypeError("Péage's fetch refuses `cache`: React Native adds a URL parameter for it")
  }
}

export function assertSignableBody(body: unknown): asserts body is string | Uint8Array | undefined {
  if (body !== undefined && typeof body !== 'string' && !(body instanceof Uint8Array)) {
    throw new TypeError('Péage can only sign string or Uint8Array bodies')
  }
}

export function assertBodyAllowed(method: string, body: string | Uint8Array | undefined): void {
  if (body !== undefined && (method === 'GET' || method === 'HEAD')) {
    throw new TypeError(`A ${method} request can't have a body`)
  }
}

export function assertContentEncodingSupported(headers: Headers): void {
  const contentEncoding = headers.get('content-encoding')
  if (contentEncoding !== null && !isSupportedContentEncoding(contentEncoding)) {
    throw new TypeError(
      "Péage's fetch refuses a Content-Encoding other than lowercase `gzip` (the only spelling iOS compresses) or `identity`: React Native only applies gzip",
    )
  }
}

export function assertGzippedBodyIsString(
  headers: Headers,
  body: string | Uint8Array | undefined,
): void {
  if (body instanceof Uint8Array && headers.get('content-encoding') === 'gzip') {
    throw new TypeError(
      "Péage's fetch refuses `Content-Encoding: gzip` on bytes: iOS sends bytes already starting with the gzip magic number unchanged, and Android drops the header",
    )
  }
}

export function assertStringBodyIsUtf8(
  headers: Headers,
  body: string | Uint8Array | undefined,
): void {
  const charsets = declaredCharsets(headers.get('content-type'))
  if (typeof body === 'string' && !charsets.every(isUtf8)) {
    throw new TypeError(
      "Péage's fetch refuses a string body in a charset other than UTF-8: React Native on Android sends it in that charset, but Péage signs UTF-8",
    )
  }
}

export function assertNotAborted(signal: AbortSignal | undefined): void {
  if (!signal?.aborted) {
    return
  }
  if (signal.reason instanceof Error) {
    throw signal.reason
  }
  const error = new Error('The request was aborted')
  error.name = 'AbortError'
  throw error
}

export async function assertSupported(native: NativeAttest): Promise<void> {
  if (!(await callNative(() => native.isSupported()))) {
    throw new PeageClientError('UNSUPPORTED', 'This device does not support attestation')
  }
}

export function assertChallengeIssued(response: Response): void {
  if (!response.ok) {
    throw new PeageClientError('SERVER', `Challenge request failed (${response.status})`)
  }
}

export function assertValidChallengeResponse(body: unknown): asserts body is { challenge: string } {
  if (!isRecord(body) || typeof body.challenge !== 'string') {
    throw new PeageClientError('SERVER', 'Challenge response has no challenge')
  }
}

export function assertSolveAccepted(response: Response): void {
  if (authenticateErrorOf(response) === 'unknown_challenge') {
    throw new PeageClientError('CHALLENGE_FAILED', 'Challenge expired before registration')
  }
  if (response.status === 401) {
    throw new PeageClientError('ATTESTATION_REJECTED', 'Attestation rejected')
  }
  if (!response.ok) {
    throw new PeageClientError('SERVER', `Registration failed (${response.status})`)
  }
}

export function assertRegistrationNotStopped(
  failedRegistrations: FailedRegistrations,
  maxRegistrationAttempts: number,
): void {
  const { count, lastError } = failedRegistrations
  if (count >= maxRegistrationAttempts) {
    throw new PeageClientError(
      'REGISTRATION_STOPPED',
      `Registration failed ${count} times in a row`,
      { cause: lastError },
    )
  }
}
