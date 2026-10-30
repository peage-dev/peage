import type { PeageErrorCode } from './types.ts'

/** Thrown by `Peage` methods when they refuse a request. */
export class PeageError extends Error {
  /** Why the request was refused. */
  readonly code: PeageErrorCode

  constructor(code: PeageErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'PeageError'
    this.code = code
  }
}

export function rethrowAs<T>(code: PeageErrorCode, check: () => T): T {
  try {
    return check()
  } catch (error) {
    if (error instanceof PeageError) {
      throw error
    }
    throw new PeageError(code, error instanceof Error ? error.message : String(error), {
      cause: error,
    })
  }
}
