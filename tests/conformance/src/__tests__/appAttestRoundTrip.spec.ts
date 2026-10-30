import { createPeage } from '@peage/express'
import { HTTP_HEADER_KEY_ID, PLATFORM_APP_ATTEST, toBase64 } from '@peage/protocol'
import { createPeageClientWithNative } from '@peage/react-native/testing'
import { createMemoryStore } from '@peage/store-memory'
import { IOS_27_AUTHENTICATOR_EXTENSIONS } from '@peage/tests'
import express from 'express'
import { gzipSync } from 'node:zlib'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { createNodeAppAttest } from '../nodeNativeAttest.ts'
import { closeServers, serve } from '../servers.ts'

const APP_ID = 'ABCDE12345.dev.peage.specs'
// A 30-second bucket boundary, so the clock-skew cases land on clean edges.
const FROZEN_TIME = new Date('2026-05-01T12:00:00Z')

function makeServer() {
  const store = createMemoryStore()
  const peage = createPeage({
    appAttest: { appId: APP_ID, environment: 'development' },
    store,
  })
  const app = express()
  app.get('/api/hello', peage.protect, (_req, res) => {
    res.json({ ok: true })
  })
  app.post('/api/echo', peage.protect, (req, res) => {
    res.json({ received: req.body })
  })
  app.use(peage.protect, (req, res) => {
    res.json({ path: req.originalUrl })
  })
  return { app, store }
}

afterEach(closeServers)

/** Changes a signed request just before it is sent, e.g. to tamper with it. */
type BeforeSending = (init: RequestInit) => RequestInit

async function startClientAndServer(
  extensions: Uint8Array | undefined,
  beforeSending: BeforeSending = (init) => init,
) {
  const { native, publicKeyFor } = createNodeAppAttest({ appId: APP_ID, extensions })
  const { app, store } = makeServer()
  const baseUrl = await serve(app)

  const keyId = await native.generateKey('', baseUrl)
  await native.markAttested(keyId, baseUrl)
  const publicKey = publicKeyFor(keyId)
  if (!publicKey) {
    throw new Error('faker did not retain the minted public key')
  }
  await store.saveAttestedKey({
    keyId,
    platform: PLATFORM_APP_ATTEST,
    appId: APP_ID,
    environment: 'development',
    publicKey: toBase64(publicKey.export({ format: 'der', type: 'spki' })),
    attestedAt: Date.now(),
  })

  const sentHeaders: Headers[] = []
  const client = createPeageClientWithNative({
    platform: PLATFORM_APP_ATTEST,
    baseUrl,
    fetch: (input, init = {}) => {
      sentHeaders.push(new Headers(init.headers))
      return fetch(input, beforeSending(init))
    },
    native,
  })

  return { client, keyId, sentHeaders }
}

/** React Native compresses a string body sent with `Content-Encoding: gzip`. */
function gzipLikeReactNative(init: RequestInit): RequestInit {
  const contentEncoding = new Headers(init.headers).get('content-encoding')
  if (contentEncoding !== 'gzip' || typeof init.body !== 'string') {
    return init
  }
  return { ...init, body: new Uint8Array(gzipSync(init.body)) }
}

describe.each([
  { authenticatorData: '37-byte header only', extensions: undefined },
  { authenticatorData: 'iOS 27 trailing extensions', extensions: IOS_27_AUTHENTICATOR_EXTENSIONS },
])('react-native client ↔ express round-trip ($authenticatorData)', ({ extensions }) => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(FROZEN_TIME)
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('verifies a GET signed by the client over an empty body', async () => {
    const { client, keyId, sentHeaders } = await startClientAndServer(extensions)
    const response = await client.fetch('/api/hello')

    expect(sentHeaders[0]?.get(HTTP_HEADER_KEY_ID)).toBe(keyId)
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ ok: true })
  })

  it('verifies a JSON POST and hands the parsed body to the route', async () => {
    const { client } = await startClientAndServer(extensions)
    const payload = { hello: 'world' }
    const response = await client.fetch('/api/echo', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    })

    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ received: payload })
  })

  it('verifies a JSON POST sent with Content-Encoding: gzip, its string body compressed after signing as React Native does', async () => {
    const { client, sentHeaders } = await startClientAndServer(extensions, gzipLikeReactNative)
    const payload = { hello: 'world' }
    const response = await client.fetch('/api/echo', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' },
      body: JSON.stringify(payload),
    })

    expect(sentHeaders[0]?.get('content-encoding')).toBe('gzip')
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ received: payload })
  })

  it('canonicalizes a lowercase method so the server still accepts it', async () => {
    const { client } = await startClientAndServer(extensions)
    const response = await client.fetch('/api/hello', { method: 'get' })
    expect(response.status).toBe(200)
  })

  it('rejects when the body is tampered with after signing', async () => {
    const { client } = await startClientAndServer(extensions, (init) => ({
      ...init,
      body: '{"hello":"tampered"}',
    }))
    const response = await client.fetch('/api/echo', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"hello":"world"}',
    })
    expect(response.status).toBe(401)
  })

  it('verifies when the client is one bucket behind the server', async () => {
    const { client } = await startClientAndServer(extensions, (init) => {
      vi.setSystemTime(new Date(FROZEN_TIME.getTime() + 30_000))
      return init
    })
    const response = await client.fetch('/api/hello')
    expect(response.status).toBe(200)
  })

  it('verifies when the client is one bucket ahead of the server', async () => {
    const { client } = await startClientAndServer(extensions, (init) => {
      vi.setSystemTime(FROZEN_TIME)
      return init
    })
    vi.setSystemTime(new Date(FROZEN_TIME.getTime() + 30_000))
    const response = await client.fetch('/api/hello')
    expect(response.status).toBe(200)
  })

  it('rejects at the first bucket beyond the skew tolerance', async () => {
    const { client } = await startClientAndServer(extensions, (init) => {
      vi.setSystemTime(new Date(FROZEN_TIME.getTime() + 60_000))
      return init
    })
    const response = await client.fetch('/api/hello')
    expect(response.status).toBe(401)
  })

  it.each([
    ['/check/a/./b', '/check/a/b'],
    ['/check/a/b/../c', '/check/a/c'],
    ['/check/%2E%2E/x', '/x'],
    ['/check?q=café', '/check?q=caf%C3%A9'],
    ['/check/a b', '/check/a%20b'],
    ['/check#top', '/check'],
    ['/check/a%zz', '/check/a%25zz'],
    ["/check/it's?q=it's", '/check/it%27s?q=it%27s'],
    ['/check/a"b{c}', '/check/a%22b%7Bc%7D'],
    ['/check/a\\b', '/check/a%5Cb'],
    ['/check/😀', '/check/%F0%9F%98%80'],
    ['/check//x', '/check//x'],
    ['/check?', '/check?'],
    ['/check/a%2fb', '/check/a%2fb'],
    ['/check/a+b?q=a+b', '/check/a+b?q=a+b'],
  ])('verifies %s, received by the server as %s', async (path, receivedPath) => {
    const { client } = await startClientAndServer(extensions)
    const response = await client.fetch(path)
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ path: receivedPath })
  })
})
