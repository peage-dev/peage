import { assertionBucket, concatBytes } from '@peage/protocol'

import type { RequestToSign } from './types.ts'

import { sha256 } from './hashing.ts'

/** Writes out the canonical signing string by hand, then hashes it. */
export function clientDataHashOf(request: RequestToSign): Uint8Array {
  const bucket = request.bucket ?? assertionBucket(Math.floor(Date.now() / 1000))
  const prefix = new TextEncoder().encode(
    `peage-request-v1\n${bucket}\n${request.method}\n${request.path}\n`,
  )
  return sha256(concatBytes(prefix, sha256(request.body)))
}
