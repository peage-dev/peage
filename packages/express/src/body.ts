import type { Request } from 'express'

import { promisify } from 'node:util'
import { gunzip, inflate } from 'node:zlib'

import {
  assertChunkedOrNoTransferCoding,
  assertDecodedWithInfo,
  assertIdentityCoding,
  assertNoTrailingBytes,
  assertNotClientAbort,
  assertNotPastDecodedLimit,
} from './asserters.ts'
import { HttpStatusError } from './errors.ts'

const DISCARDED_BODY_LIMIT_FACTOR = 3

type Decompress = (
  body: Uint8Array,
  options: { maxOutputLength: number; info: true },
) => Promise<unknown>
type BodyDecoder = (body: Uint8Array, maxBytes: number) => Promise<Uint8Array>

async function keepUnchanged(body: Uint8Array): Promise<Uint8Array> {
  return body
}

async function decompressOrReject(
  decompress: Decompress,
  body: Uint8Array,
  maxBytes: number,
): Promise<unknown> {
  try {
    return await decompress(body, { maxOutputLength: maxBytes, info: true })
  } catch (error) {
    assertNotPastDecodedLimit(error)
    throw new HttpStatusError(400)
  }
}

function decompressingWith(decompress: Decompress): BodyDecoder {
  return async (body, maxBytes) => {
    const decoded = await decompressOrReject(decompress, body, maxBytes)
    assertDecodedWithInfo(decoded)
    assertNoTrailingBytes(decoded.engine.bytesWritten, body.length)
    return new Uint8Array(decoded.buffer)
  }
}

const gunzipBounded = decompressingWith(promisify(gunzip))
const inflateBounded = decompressingWith(promisify(inflate))

function contentCodingOf(req: Request): string {
  return req.header('content-encoding')?.toLowerCase() ?? 'identity'
}

function decoderFor(req: Request): BodyDecoder {
  switch (contentCodingOf(req)) {
    case 'identity':
      return keepUnchanged
    case 'gzip':
      return gunzipBounded
    case 'deflate':
      return inflateBounded
    default:
      throw new HttpStatusError(415)
  }
}

async function* readChunks(req: Request): AsyncGenerator<Buffer> {
  try {
    yield* req
  } catch (error) {
    assertNotClientAbort(error)
    throw error
  }
}

async function readEncodedBodyBounded(req: Request, maxBytes: number): Promise<Uint8Array> {
  const discardedLimit = maxBytes * DISCARDED_BODY_LIMIT_FACTOR
  if (Number(req.header('content-length')) > discardedLimit) {
    throw new HttpStatusError(413)
  }

  const chunks: Buffer[] = []
  let total = 0
  for await (const chunk of readChunks(req)) {
    total += chunk.length
    if (total > discardedLimit) {
      throw new HttpStatusError(413)
    }
    if (total <= maxBytes) {
      chunks.push(chunk)
    }
  }
  if (total > maxBytes) {
    throw new HttpStatusError(413)
  }
  return new Uint8Array(Buffer.concat(chunks))
}

export async function readDecodedBodyBounded(req: Request, maxBytes: number): Promise<Uint8Array> {
  assertChunkedOrNoTransferCoding(req.header('transfer-encoding'))
  const decode = decoderFor(req)
  const body = await readEncodedBodyBounded(req, maxBytes)
  return body.length === 0 ? body : decode(body, maxBytes)
}

export async function readIdentityBodyBounded(req: Request, maxBytes: number): Promise<Uint8Array> {
  assertChunkedOrNoTransferCoding(req.header('transfer-encoding'))
  assertIdentityCoding(contentCodingOf(req))
  return readEncodedBodyBounded(req, maxBytes)
}
