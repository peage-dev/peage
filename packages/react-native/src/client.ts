import {
  assertionBucket,
  canonicalRequestBytes,
  CHALLENGE_PATH,
  HTTP_HEADER_ASSERTION,
  HTTP_HEADER_DEBUG_TOKEN,
  HTTP_HEADER_KEY_ID,
  HTTP_HEADER_PROTOCOL_VERSION,
  type Platform,
  PROTOCOL_VERSION,
  SOLVE_PATH,
} from '@peage/protocol'

import type { NativeAttest, PeageClient, PeageClientOptions, RequestToSend } from './types.ts'

import { assertNotAborted } from './asserters.ts'
import { generateAssertion } from './assertionQueue.ts'
import { PeageClientError } from './errors.ts'
import { authenticateErrorOf } from './headers.ts'
import { callNative, nativeErrorCode, sha256 } from './native.ts'
import { createRegistration } from './registration.ts'
import { normalizeBaseUrl, serverLocationOf, serverUrlOf } from './requestTarget.ts'
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
  const assertion = await generateAssertion(native, keyId, clientDataHash, request.signal)

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
  const { debugToken } = options

  const { register, forgetKey, clearKey } = createRegistration({
    native,
    platform,
    challengeUrl: serverUrlOf(options.challengePath ?? CHALLENGE_PATH, server),
    solveUrl: serverUrlOf(options.solvePath ?? SOLVE_PATH, server),
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

  function isSupported(): Promise<boolean> {
    return callNative(() => native.isSupported())
  }

  async function sendToServer(
    request: RequestToSend,
    peageHeaders: Record<string, string>,
  ): Promise<Response> {
    const headers = new Headers(request.headers)
    for (const [name, value] of Object.entries(peageHeaders)) {
      headers.set(name, value)
    }
    const url = server.origin + request.path
    try {
      return await fetchFromServer(url, {
        method: request.method,
        headers,
        body: request.body,
        signal: request.signal,
        credentials: request.credentials,
      })
    } catch (error) {
      if (isCancellation(error)) {
        throw error
      }
      throw new PeageClientError('NETWORK', `Péage could not reach ${url}`, {
        cause: error,
      })
    }
  }

  async function sendSigned(request: RequestToSend) {
    assertNotAborted(request.signal)
    const signed = await sign(request)
    const response = await sendToServer(request, signed)
    return { response, keyId: signed[HTTP_HEADER_KEY_ID] }
  }

  async function signedFetch(request: RequestToSend): Promise<Response> {
    const first = await sendSigned(request)
    if (!isUnknownKeyResponse(first.response)) {
      return first.response
    }
    await forgetKey(first.keyId)
    const retry = await sendSigned(request)
    return retry.response
  }

  function fetchWithDebugToken(request: RequestToSend, token: string): Promise<Response> {
    return sendToServer(request, {
      [HTTP_HEADER_DEBUG_TOKEN]: token,
      [HTTP_HEADER_PROTOCOL_VERSION]: PROTOCOL_VERSION,
    })
  }

  async function peageFetch(input: string | URL | Request, init: RequestInit = {}) {
    const request = await requestToSend(input, init, server)
    if (debugToken !== undefined) {
      return fetchWithDebugToken(request, debugToken)
    }
    return signedFetch(request)
  }

  return {
    isSupported,
    register,
    fetch: peageFetch,
    clearKey,
  }
}
