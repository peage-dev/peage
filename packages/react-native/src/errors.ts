import type { PeageClientErrorCode } from './types.ts'

/** Thrown by `PeageClient` methods when attesting, registering or reaching the server fails. */
export class PeageClientError extends Error {
  /** Why the client failed. */
  readonly code: PeageClientErrorCode

  constructor(code: PeageClientErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'PeageClientError'
    this.code = code
  }
}

export function abortErrorOf(signal: AbortSignal): unknown {
  if (signal.reason instanceof Error) {
    return signal.reason
  }
  const error = new Error('The request was aborted')
  error.name = 'AbortError'
  return error
}
