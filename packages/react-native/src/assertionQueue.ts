import { toBase64url } from '@peage/protocol'

import type { NativeAttest } from './types.ts'

import { assertNotAborted } from './asserters.ts'
import { abortErrorOf } from './errors.ts'
import { callNative } from './native.ts'

// Concurrent App Attest assertions can fail with DCError 0 (unknownSystemFailure).
const assertionQueues = new WeakMap<NativeAttest, Promise<unknown>>()

function untilSettledOrAborted(previous: Promise<unknown>, signal: AbortSignal): Promise<unknown> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(abortErrorOf(signal))
      return
    }
    function rejectWithAbortError() {
      reject(abortErrorOf(signal))
    }
    function resolveAndStopListening() {
      signal.removeEventListener('abort', rejectWithAbortError)
      resolve(undefined)
    }
    signal.addEventListener('abort', rejectWithAbortError, { once: true })
    previous.then(resolveAndStopListening, resolveAndStopListening)
  })
}

export function generateAssertion(
  native: NativeAttest,
  keyId: string,
  clientDataHash: Uint8Array,
  signal: AbortSignal | undefined,
): Promise<string> {
  const previousAssertion = assertionQueues.get(native) ?? Promise.resolve()
  const turn =
    signal === undefined ? previousAssertion : untilSettledOrAborted(previousAssertion, signal)
  const assertion = turn.then(() => {
    assertNotAborted(signal)
    return callNative(() => native.generateAssertion(keyId, toBase64url(clientDataHash)))
  })
  assertionQueues.set(
    native,
    previousAssertion.then(() => assertion).catch(() => undefined),
  )
  return assertion
}
