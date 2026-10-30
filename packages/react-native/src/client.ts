import {
  assertionBucket,
  canonicalRequestBytes,
  HTTP_HEADER_ASSERTION,
  HTTP_HEADER_KEY_ID,
  HTTP_HEADER_PROTOCOL_VERSION,
  type Platform,
  PROTOCOL_VERSION,
  toBase64url,
} from '@peage/protocol'

import type { NativeAttest, PeageClient, PeageClientOptions, RequestToSend } from './types.ts'

import { assertNotAborted } from './asserters.ts'
import { PeageClientError } from './errors.ts'
import { authenticateErrorOf } from './headers.ts'
import { callNative, nativeErrorCode, sha256 } from './native.ts'
import { createRegistration } from './registration.ts'
import { normalizeBaseUrl, serverLocationOf } from './requestTarget.ts'
import { requestToSend } from './requestToSend.ts'

const DEFAULT_MAX_REGISTRATION_ATTEMPTS = 3

type SignedRequestHeaders = {
  [HTTP_HEADER_KEY_ID]: string
  [HTTP_HEADER_ASSERTION]: string
  [HTTP_HEADER_PROTOCOL_VERSION]: string
}

function isCancellation(error: unknown): boolean {
  return error instanceof Error && (error.name === 'AbortError' || error.name === 'TimeoutError')
}

function isUnknownKeyResponse(response: Response): boolean {
  return authenticateErrorOf(response) === 'unknown_key'
}

function encodeBody(body: string | Uint8Array | undefined): Uint8Array {
  if (body === undefined) {
    return new Uint8Array()
  }
  return typeof body === 'string' ? new TextEncoder().encode(body) : body
}

async function signWithKey(
  native: NativeAttest,
  keyId: string,
  request: RequestToSend,
): Promise<SignedRequestHeaders> {
  const bodyDigest = await sha256(native, encodeBody(request.body))
  const bucket = assertionBucket(Math.floor(Date.now() / 1000))
  const clientDataHash = await sha256(
    native,
    canonicalRequestBytes({ bucket, method: request.method, path: request.path, bodyDigest }),
  )
  const assertion = await callNative(() =>
    native.generateAssertion(keyId, toBase64url(clientDataHash)),
  )

  return {
    [HTTP_HEADER_KEY_ID]: keyId,
    [HTTP_HEADER_ASSERTION]: assertion,
    [HTTP_HEADER_PROTOCOL_VERSION]: PROTOCOL_VERSION,
  }
}

/**
 * `createPeageClient` with the native module and platform passed in, for tests outside
 * React Native.
 */
export function createPeageClientWithNative(
  options: PeageClientOptions & { native: NativeAttest; platform: Platform },
): PeageClient {
  const { native, platform } = options
  const fetchFromServer = options.fetch ?? globalThis.fetch
  const server = serverLocationOf(options.baseUrl)
  const keyScope = options.keyScope ?? normalizeBaseUrl(server)
  const maxRegistrationAttempts =
    options.maxRegistrationAttempts ?? DEFAULT_MAX_REGISTRATION_ATTEMPTS

  const { register, forgetKey, clearKey } = createRegistration({
    native,
    platform,
    baseUrl: options.baseUrl,
    keyScope,
    fetchFromServer,
    maxRegistrationAttempts,
  })

  async function sign(request: RequestToSend): Promise<SignedRequestHeaders> {
    const keyId = await register()
    try {
      return await signWithKey(native, keyId, request)
    } catch (error) {
      if (nativeErrorCode(error) !== 'E_INVALID_KEY') {
        throw error
      }
      await forgetKey(keyId)
      return signWithKey(native, await register(), request)
    }
  }

  async function sendSigned(request: RequestToSend) {
    assertNotAborted(request.signal)
    const headers = new Headers(request.headers)
    const signed = await sign(request)
    for (const [name, value] of Object.entries(signed)) {
      headers.set(name, value)
    }
    try {
      const response = await fetchFromServer(`${server.origin}${request.path}`, {
        method: request.method,
        headers,
        body: request.body,
        signal: request.signal,
        credentials: request.credentials,
      })
      return { response, keyId: signed[HTTP_HEADER_KEY_ID] }
    } catch (error) {
      if (isCancellation(error)) {
        throw error
      }
      throw new PeageClientError('NETWORK', `Péage could not reach ${request.path}`, {
        cause: error,
      })
    }
  }

  async function signedFetch(input: string | URL | Request, init: RequestInit = {}) {
    const request = await requestToSend(input, init, server)
    const first = await sendSigned(request)
    if (!isUnknownKeyResponse(first.response)) {
      return first.response
    }
    await forgetKey(first.keyId)
    const retry = await sendSigned(request)
    return retry.response
  }

  return {
    isSupported: () => callNative(() => native.isSupported()),
    register,
    fetch: signedFetch,
    clearKey,
  }
}
