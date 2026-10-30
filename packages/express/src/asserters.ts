import type { Request } from 'express'

import { assertPlatform, type VerifiedRequest } from '@peage/core'
import { isRecord, type Platform } from '@peage/protocol'

import { HttpStatusError } from './errors.ts'

type SolveRequest = {
  platform: Platform
  challenge: string
  keyId: string
  proof: string
}

export function assertUnpaddedBase64url(value: string): void {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) {
    throw new HttpStatusError(400)
  }
}

export function assertJsonObject(value: unknown): asserts value is Record<string, unknown> {
  if (!isRecord(value)) {
    throw new HttpStatusError(400)
  }
}

export function assertValidSolveRequest(
  body: Record<string, unknown>,
): asserts body is SolveRequest {
  assertPlatform(body.platform)
  if (
    typeof body.challenge !== 'string' ||
    typeof body.keyId !== 'string' ||
    typeof body.proof !== 'string'
  ) {
    throw new HttpStatusError(400)
  }
}

export function assertVerifiedByProtect(
  verified: VerifiedRequest | undefined,
): asserts verified is VerifiedRequest {
  if (verified === undefined) {
    throw new Error('Péage protect must run before this handler')
  }
}

export function assertBodyUnread(req: Request): void {
  if (req.body !== undefined || req.readableEnded) {
    throw new Error(
      'Péage protect must run before any body parser: the request body was already read',
    )
  }
}

function hasErrorCode(error: unknown, code: string): boolean {
  return error instanceof Error && 'code' in error && error.code === code
}

/** Node fails the request stream with `ECONNRESET` when the client disconnects mid-upload. */
export function assertNotClientAbort(error: unknown): void {
  if (hasErrorCode(error, 'ECONNRESET')) {
    throw new HttpStatusError(400)
  }
}

/** zlib fails with `ERR_BUFFER_TOO_LARGE` once the output would pass `maxOutputLength`. */
export function assertNotPastDecodedLimit(error: unknown): void {
  if (hasErrorCode(error, 'ERR_BUFFER_TOO_LARGE')) {
    throw new HttpStatusError(413)
  }
}

const HTTP_SCHEME = /^https?$/i
const HOST_AND_PORT = /^(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::[0-9]+)?$/

export function assertHttpAuthority(scheme: string, authority: string): void {
  if (!HTTP_SCHEME.test(scheme) || !HOST_AND_PORT.test(authority)) {
    throw new HttpStatusError(400)
  }
}

export function assertDecodedWithInfo(
  value: unknown,
): asserts value is { buffer: Uint8Array; engine: { bytesWritten: number } } {
  if (
    !isRecord(value) ||
    !(value.buffer instanceof Uint8Array) ||
    !isRecord(value.engine) ||
    typeof value.engine.bytesWritten !== 'number'
  ) {
    throw new Error('zlib did not return its result with info')
  }
}

export function assertNoTrailingBytes(bytesDecoded: number, bodyLength: number): void {
  if (bytesDecoded !== bodyLength) {
    throw new HttpStatusError(400)
  }
}

/**
 * RFC 9112 §6.1: a server answers 501 to a transfer coding it doesn't understand.
 * Node's parser answers 400 and closes the connection to a value it can't frame,
 * such as `gzip`, so this 501 never reaches that client.
 */
export function assertChunkedOrNoTransferCoding(transferEncoding: string | undefined): void {
  if (transferEncoding !== undefined && transferEncoding.toLowerCase() !== 'chunked') {
    throw new HttpStatusError(501)
  }
}

export function assertIdentityCoding(contentCoding: string): void {
  if (contentCoding !== 'identity') {
    throw new HttpStatusError(415)
  }
}

export function assertValidMaxBodyBytes(maxBodyBytes: number): void {
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes <= 0) {
    throw new Error('maxBodyBytes must be a positive integer')
  }
}
