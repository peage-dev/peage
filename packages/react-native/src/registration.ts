import {
  CHALLENGE_PATH,
  HTTP_HEADER_PROTOCOL_VERSION,
  PLATFORM_APP_ATTEST,
  type Platform,
  PROTOCOL_VERSION,
  SOLVE_PATH,
  toBase64url,
} from '@peage/protocol'

import type { FailedRegistrations, NativeAttest } from './types.ts'

import {
  assertChallengeIssued,
  assertRegistrationNotStopped,
  assertSolveAccepted,
  assertSupported,
  assertValidChallengeResponse,
} from './asserters.ts'
import { PeageClientError } from './errors.ts'
import { callNative, nativeErrorCode, sha256 } from './native.ts'

type KeyScopeState = {
  pendingKeyId: Promise<string> | null
  keyForgettingQueue: Promise<void>
  failedRegistrations: FailedRegistrations
  /** Apple's guidance: after a server-unavailable error, attest the same key again. */
  appAttestKeyIdAwaitingAttestation: string | null
}

const NO_FAILED_REGISTRATIONS: FailedRegistrations = { count: 0, lastError: null }

const keyScopeStates = new WeakMap<NativeAttest, Map<string, KeyScopeState>>()

function newKeyScopeState(): KeyScopeState {
  return {
    pendingKeyId: null,
    keyForgettingQueue: Promise.resolve(),
    failedRegistrations: NO_FAILED_REGISTRATIONS,
    appAttestKeyIdAwaitingAttestation: null,
  }
}

function canAttestSameKeyAgain(platform: Platform, attestationError: unknown): boolean {
  return (
    platform === PLATFORM_APP_ATTEST && nativeErrorCode(attestationError) === 'E_SERVER_UNAVAILABLE'
  )
}

function keyScopeStatesOf(native: NativeAttest): Map<string, KeyScopeState> {
  let statesOfNative = keyScopeStates.get(native)
  if (statesOfNative === undefined) {
    statesOfNative = new Map()
    keyScopeStates.set(native, statesOfNative)
  }
  return statesOfNative
}

function keyScopeStateOf(native: NativeAttest, keyScope: string): KeyScopeState {
  const statesOfNative = keyScopeStatesOf(native)
  let state = statesOfNative.get(keyScope)
  if (state === undefined) {
    state = newKeyScopeState()
    statesOfNative.set(keyScope, state)
  }
  return state
}

type RegistrationOptions = {
  native: NativeAttest
  platform: Platform
  baseUrl: string
  keyScope: string
  fetchFromServer: typeof fetch
  maxRegistrationAttempts: number
}

type Registration = {
  register: () => Promise<string>
  forgetKey: (keyId: string) => Promise<void>
  clearKey: () => Promise<void>
}

export function createRegistration(options: RegistrationOptions): Registration {
  const { native, platform, baseUrl, keyScope, fetchFromServer, maxRegistrationAttempts } = options
  const state = keyScopeStateOf(native, keyScope)

  async function postJson(path: string, body: unknown): Promise<Response> {
    try {
      return await fetchFromServer(`${baseUrl}${path}`, {
        body: JSON.stringify(body),
        headers: {
          'content-type': 'application/json',
          [HTTP_HEADER_PROTOCOL_VERSION]: PROTOCOL_VERSION,
        },
        method: 'POST',
      })
    } catch (error) {
      throw new PeageClientError('NETWORK', `Péage could not reach ${path}`, { cause: error })
    }
  }

  async function fetchChallenge(): Promise<string> {
    const response = await postJson(CHALLENGE_PATH, { platform })
    assertChallengeIssued(response)
    let body: unknown
    try {
      body = await response.json()
    } catch (error) {
      throw new PeageClientError('SERVER', 'Challenge response is not JSON', {
        cause: error,
      })
    }
    assertValidChallengeResponse(body)
    return body.challenge
  }

  async function attestKey(keyId: string, challengeHash: string): Promise<string> {
    try {
      return await callNative(() => native.attestKey(keyId, challengeHash))
    } catch (error) {
      if (canAttestSameKeyAgain(platform, error)) {
        state.appAttestKeyIdAwaitingAttestation = keyId
      }
      throw error
    }
  }

  async function registerNewKey(): Promise<string> {
    const challenge = await fetchChallenge()
    const challengeHash = toBase64url(await sha256(native, new TextEncoder().encode(challenge)))
    const keyId =
      state.appAttestKeyIdAwaitingAttestation ??
      (await callNative(() => native.generateKey(challengeHash, keyScope)))
    state.appAttestKeyIdAwaitingAttestation = null
    const proof = await attestKey(keyId, challengeHash)

    assertSolveAccepted(await postJson(SOLVE_PATH, { challenge, keyId, platform, proof }))
    await callNative(() => native.markAttested(keyId, keyScope))
    return keyId
  }

  async function registerWithinLimit(): Promise<string> {
    await assertSupported(native)
    assertRegistrationNotStopped(state.failedRegistrations, maxRegistrationAttempts)
    try {
      const keyId = await registerNewKey()
      state.failedRegistrations = NO_FAILED_REGISTRATIONS
      return keyId
    } catch (error) {
      if (!(error instanceof PeageClientError && error.code === 'NETWORK')) {
        state.failedRegistrations = {
          count: state.failedRegistrations.count + 1,
          lastError: error,
        }
      }
      throw error
    }
  }

  async function storedOrNewKeyId(): Promise<string> {
    const storedKeyId = await callNative(() => native.getKeyId(keyScope))
    return storedKeyId ?? registerWithinLimit()
  }

  function register(): Promise<string> {
    state.pendingKeyId ??= storedOrNewKeyId().finally(() => {
      state.pendingKeyId = null
    })
    return state.pendingKeyId
  }

  function forgetKey(keyId: string): Promise<void> {
    const forgetting = state.keyForgettingQueue.then(async () => {
      if ((await callNative(() => native.getKeyId(keyScope))) === keyId) {
        await callNative(() => native.clearKeyId(keyScope))
      }
    })
    state.keyForgettingQueue = forgetting.catch(() => undefined)
    return forgetting
  }

  async function clearKey(): Promise<void> {
    await state.pendingKeyId?.catch(() => undefined)
    state.failedRegistrations = NO_FAILED_REGISTRATIONS
    await callNative(() => native.clearKeyId(keyScope))
  }

  return { register, forgetKey, clearKey }
}
