import { fromBase64url, isRecord, toBase64url } from '@peage/protocol'

import type { NativeAttest } from './types.ts'

import { PeageClientError } from './errors.ts'

export async function callNative<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation()
  } catch (error) {
    throw new PeageClientError('NATIVE', 'Péage native module failed', { cause: error })
  }
}

export function nativeErrorCode(error: unknown): unknown {
  return error instanceof PeageClientError && isRecord(error.cause) ? error.cause.code : undefined
}

export async function sha256(native: NativeAttest, data: Uint8Array): Promise<Uint8Array> {
  return fromBase64url(await callNative(() => native.sha256(toBase64url(data))))
}
