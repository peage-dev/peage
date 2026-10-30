import { assertCanonicalRequest } from '@peage/protocol'

import type { RequestToSend, ServerLocation } from './types.ts'

import {
  assertBodyAllowed,
  assertContentEncodingSupported,
  assertGzippedBodyIsString,
  assertSignableBody,
  assertStringBodyIsUtf8,
  assertSupportedOptions,
} from './asserters.ts'
import { serverPathOf } from './requestTarget.ts'

async function bodyOf(request: Request | undefined, init: RequestInit): Promise<unknown> {
  if (init.body !== undefined && init.body !== null) {
    return init.body
  }
  if (request === undefined) {
    return undefined
  }
  const bytes = new Uint8Array(await request.arrayBuffer())
  return bytes.length > 0 ? bytes : undefined
}

function requestAndUrlOf(input: string | URL | Request): {
  request: Request | undefined
  url: string
} {
  if (input instanceof Request) {
    return { request: input, url: input.url }
  }
  return { request: undefined, url: input.toString() }
}

export async function requestToSend(
  input: string | URL | Request,
  init: RequestInit,
  server: ServerLocation,
): Promise<RequestToSend> {
  assertSupportedOptions(init)
  const { request, url } = requestAndUrlOf(input)
  const path = serverPathOf(url, server)
  const method = (init.method ?? request?.method ?? 'GET').toUpperCase()
  assertCanonicalRequest({ method, path })
  const headers = new Headers(init.headers ?? request?.headers)
  assertContentEncodingSupported(headers)
  const body = await bodyOf(request, init)
  assertSignableBody(body)
  assertBodyAllowed(method, body)
  assertGzippedBodyIsString(headers, body)
  assertStringBodyIsUtf8(headers, body)
  return {
    method,
    path,
    body,
    headers,
    signal: init.signal ?? request?.signal ?? undefined,
    credentials: init.credentials ?? request?.credentials,
  }
}
