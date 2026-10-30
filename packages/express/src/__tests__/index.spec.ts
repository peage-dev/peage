import {
  concatBytes,
  HTTP_HEADER_ASSERTION,
  HTTP_HEADER_KEY_ID,
  PLATFORM_APP_ATTEST,
  PLATFORM_PLAY_INTEGRITY,
  toBase64,
  toBase64url,
} from '@peage/protocol'
import { createMemoryStore } from '@peage/store-memory'
import {
  createKeyAttestationRoot,
  createPlayIntegrityKeys,
  keyIdFor,
  listenOnLoopback,
  newDeviceKey,
  playIntegrityRegistrationProof,
  portOf,
  signAppAttestRequest,
} from '@peage/tests'
import express, {
  type Express,
  type NextFunction,
  type Request,
  type RequestHandler,
  type Response,
} from 'express'
import { generateKeyPairSync, type KeyObject } from 'node:crypto'
import {
  request as httpRequest,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http'
import { connect } from 'node:net'
import { setTimeout as delay } from 'node:timers/promises'
import { brotliCompressSync, deflateSync, gzipSync } from 'node:zlib'
import request from 'supertest'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { createPeage, type PeageStore, verifiedRequestOf } from '../index.ts'

const APP_ID = 'ABCDE12345.dev.peage.specs'
const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
const KEY_ID = keyIdFor(publicKey)
const UNKNOWN_KEY_ID = keyIdFor(newDeviceKey())
const PACKAGE_NAME = 'dev.peage.specs'
const playIntegrityKeys = createPlayIntegrityKeys()
const keyAttestationRoot = createKeyAttestationRoot()
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024
const PROTOCOL_MAX_BODY_BYTES = 128 * 1024

async function registerTestKey(store: PeageStore) {
  await store.saveAttestedKey({
    keyId: KEY_ID,
    platform: PLATFORM_APP_ATTEST,
    appId: APP_ID,
    environment: 'development',
    publicKey: toBase64(publicKey.export({ format: 'der', type: 'spki' })),
    attestedAt: Date.now(),
  })
}

const servers: Server[] = []

afterEach(() => {
  for (const server of servers.splice(0)) {
    server.closeAllConnections()
    server.close()
  }
})

async function serve(app: Express): Promise<Server> {
  const server = await listenOnLoopback(app)
  servers.push(server)
  return server
}

type AppOptions = { maxBodyBytes?: number; store?: PeageStore; readBodyFirst?: RequestHandler }

function makeApp(options: AppOptions = {}) {
  const store = options.store ?? createMemoryStore()
  const peage = createPeage({
    appAttest: { appId: APP_ID, environment: 'development' },
    maxBodyBytes: options.maxBodyBytes,
    store,
  })

  const app = express()
  if (options.readBodyFirst) {
    app.use(options.readBodyFirst)
  }
  app.post('/peage/challenge', peage.challenge)
  app.post('/peage/solve', peage.solve)
  app.get('/api/hello', peage.protect, (_req, res) => {
    res.json({ ok: true, peage: res.locals.peage })
  })
  app.post('/api/echo', peage.protect, (req, res) => {
    res.json({ received: req.body })
  })
  const router = express.Router()
  router.get('/hello', peage.protect, (_req, res) => {
    res.json({ ok: true })
  })
  app.use('/v1', router)
  app.get('/', peage.protect, (_req, res) => {
    res.json({ ok: true })
  })
  app.use(peage.protect, (_req, res) => {
    res.json({ ok: true })
  })
  return { app, store }
}

async function makeAppWithKey(options: AppOptions = {}): Promise<Express> {
  const { app, store } = makeApp(options)
  await registerTestKey(store)
  return app
}

function makeAndroidApp() {
  const peage = createPeage({
    playIntegrity: {
      packageName: PACKAGE_NAME,
      decryptionKey: playIntegrityKeys.decryptionKey,
      verificationKey: playIntegrityKeys.verificationKey,
      keyAttestation: {
        trustedRoots: [keyAttestationRoot.certificate.toString()],
        loadRevokedSerialNumbers: async () => new Set<string>(),
      },
    },
    store: createMemoryStore(),
  })

  const app = express()
  app.post('/peage/challenge', peage.challenge)
  app.post('/peage/solve', peage.solve)
  return app
}

function androidProof(challenge: string, deviceKey: KeyObject): string {
  const proof = playIntegrityRegistrationProof({
    challenge,
    deviceKey,
    packageName: PACKAGE_NAME,
    keys: playIntegrityKeys,
    keyAttestationRoot,
  })
  return toBase64url(proof)
}

type SignedRequestInput = { method: string; path: string; body: string | Uint8Array }

function signedAssertion(input: SignedRequestInput): Uint8Array {
  const { assertion } = signAppAttestRequest({
    appId: APP_ID,
    body: typeof input.body === 'string' ? new TextEncoder().encode(input.body) : input.body,
    method: input.method,
    path: input.path,
    privateKey,
  })
  return assertion
}

function signedHeaders(input: SignedRequestInput) {
  return {
    [HTTP_HEADER_KEY_ID]: KEY_ID,
    [HTTP_HEADER_ASSERTION]: toBase64url(signedAssertion(input)),
  }
}

function signedEchoHeaders(body: string | Uint8Array) {
  return signedHeaders({ method: 'POST', path: '/api/echo', body })
}

const MAX_SIGNING_ATTEMPTS = 1000

/** ECDSA signatures are random: re-signs until the base64url encoding has the wanted shape. */
function encodedHelloAssertionWhere(hasWantedShape: (encoded: string) => boolean): string {
  for (let attempt = 0; attempt < MAX_SIGNING_ATTEMPTS; attempt++) {
    const encoded = toBase64url(signedAssertion({ method: 'GET', path: '/api/hello', body: '' }))
    if (hasWantedShape(encoded)) {
      return encoded
    }
  }
  throw new Error('No signature produced the wanted encoding')
}

function withSpaceInside(value: string): string {
  return `${value.slice(0, 4)} ${value.slice(4)}`
}

function inStandardAlphabet(base64url: string): string {
  return base64url.replaceAll('-', '+').replaceAll('_', '/')
}

function challengeBodyOfLength(length: number): string {
  const empty = JSON.stringify({ platform: PLATFORM_APP_ATTEST, padding: '' })
  return JSON.stringify({
    platform: PLATFORM_APP_ATTEST,
    padding: 'x'.repeat(length - empty.length),
  })
}

const consumeBodyStream: RequestHandler = (req, _res, next) => {
  req.on('end', () => next())
  req.resume()
}

const setBodyWithoutReading: RequestHandler = (req, _res, next) => {
  req.body = { to: 'attacker', amount: 1000000 }
  next()
}

function recordErrors(app: Express): unknown[] {
  const errors: unknown[] = []
  app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    errors.push(error)
    res.status(500).end()
  })
  return errors
}

async function uploadInChunks(
  server: Server,
  chunkCount: number,
): Promise<{ status?: number; connection?: string }> {
  const outgoing = httpRequest({
    port: portOf(server),
    method: 'POST',
    path: '/api/echo',
    headers: {
      ...signedEchoHeaders(''),
      'content-type': 'application/octet-stream',
      'transfer-encoding': 'chunked',
    },
  })
  const response = new Promise<{ status?: number; connection?: string }>((resolve, reject) => {
    outgoing.on('response', (incoming) =>
      resolve({ status: incoming.statusCode, connection: incoming.headers.connection }),
    )
    outgoing.on('error', reject)
  })
  for (let sent = 0; sent < chunkCount; sent++) {
    outgoing.write(Buffer.alloc(16))
    // oxlint-disable-next-line no-await-in-loop
    await delay(5)
  }
  outgoing.end()
  return response
}

function requestHead(method: string, target: string, headers: Record<string, string>): string {
  const headerLines = Object.entries(headers).map(([name, value]) => `${name}: ${value}`)
  return [`${method} ${target} HTTP/1.1`, 'Host: 127.0.0.1', ...headerLines, '', ''].join('\r\n')
}

type ResponseHead = { status: number; connection?: string }

function responseHeadOf(response: string): ResponseHead {
  return {
    status: Number(/^HTTP\/1\.1 (\d{3}) /.exec(response)?.[1]),
    connection: /^connection: (.*)$/im.exec(response)?.[1],
  }
}

async function responseOverSocket(server: Server, head: string): Promise<ResponseHead> {
  const socket = connect(portOf(server), '127.0.0.1')
  socket.setTimeout(1000, () => socket.destroy())
  let response = ''
  socket.on('data', (data: Buffer) => {
    response += data.toString('latin1')
  })
  const closed = new Promise((resolve) => socket.once('close', resolve))
  socket.write(head)
  await closed
  return responseHeadOf(response)
}

async function statusOverSocket(server: Server, head: string): Promise<number> {
  const { status } = await responseOverSocket(server, head)
  return status
}

function chunkedBody(text: string): string {
  return `${Buffer.byteLength(text).toString(16)}\r\n${text}\r\n0\r\n\r\n`
}

function gzipText(text: string): Uint8Array {
  return new Uint8Array(gzipSync(text))
}

async function postEncoded(
  server: Server,
  path: string,
  headers: Record<string, string>,
  body: Uint8Array,
): Promise<globalThis.Response> {
  return fetch(`http://127.0.0.1:${portOf(server)}${path}`, { method: 'POST', headers, body })
}

type SocketUpload = ResponseHead & { uploadFinished: boolean }

async function uploadSlowlyOverSocket(
  server: Server,
  path: string,
  headers: Record<string, string>,
): Promise<SocketUpload> {
  const chunkCount = 50
  const chunkSize = 1024
  const socket = connect(portOf(server), '127.0.0.1')
  // Writes after the server closed the connection fail with EPIPE or ECONNRESET.
  socket.on('error', () => undefined)
  let response = ''
  socket.on('data', (data: Buffer) => {
    response += data.toString('latin1')
  })
  const closed = new Promise((resolve) => socket.once('close', resolve))

  socket.write(
    requestHead('POST', path, {
      ...headers,
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(chunkCount * chunkSize),
    }),
  )
  let sent = 0
  while (sent < chunkCount && socket.writable) {
    socket.write(Buffer.alloc(chunkSize))
    sent++
    // oxlint-disable-next-line no-await-in-loop
    await delay(5)
  }
  socket.end()
  await closed
  return { ...responseHeadOf(response), uploadFinished: sent === chunkCount }
}

async function abortUpload(server: Server, path: string): Promise<ServerResponse> {
  const received = new Promise<ServerResponse>((resolve) => {
    server.once('request', (_req: IncomingMessage, res: ServerResponse) => resolve(res))
  })
  const head = requestHead('POST', path, {
    'Content-Type': 'application/json',
    'Content-Length': '100',
    ...signedHeaders({ method: 'POST', path, body: '' }),
  })
  const socket = connect(portOf(server), '127.0.0.1')
  socket.write(`${head}{"platform"`)
  const res = await received
  socket.destroy()
  await vi.waitFor(() => expect(res.writableEnded).toBe(true))
  return res
}

describe('createPeage', () => {
  it('refuses a maxBodyBytes that is not a positive integer', () => {
    for (const maxBodyBytes of [Number.NaN, 0, -1, 1.5]) {
      expect(() => makeApp({ maxBodyBytes })).toThrow(/positive integer/)
    }
  })
})

describe('peage.challenge', () => {
  it('issues a challenge for a valid platform', async () => {
    const { app } = makeApp()
    const response = await request(await serve(app))
      .post('/peage/challenge')
      .send({ platform: PLATFORM_APP_ATTEST })
    expect(response.status).toBe(200)
    expect(response.body.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })

  it('still works when a JSON parser already read the body', async () => {
    const { app } = makeApp({ readBodyFirst: express.json() })
    const response = await request(await serve(app))
      .post('/peage/challenge')
      .send({ platform: PLATFORM_APP_ATTEST })
    expect(response.status).toBe(200)
  })

  it('rejects an empty, malformed, non-object or null body with 400', async () => {
    const { app } = makeApp()
    const empty = await request(await serve(app)).post('/peage/challenge')
    const malformed = await request(await serve(app))
      .post('/peage/challenge')
      .set('content-type', 'application/json')
      .send('not-json')
    const notAnObject = await request(await serve(app))
      .post('/peage/challenge')
      .set('content-type', 'application/json')
      .send('"a string"')
    const nullBody = await request(await serve(app))
      .post('/peage/challenge')
      .set('content-type', 'application/json')
      .send('null')
    expect([empty.status, malformed.status, notAnObject.status, nullBody.status]).toStrictEqual([
      400, 400, 400, 400,
    ])
  })

  it('rejects an unknown platform and a disabled platform with 400', async () => {
    const { app } = makeApp()
    const unknown = await request(await serve(app))
      .post('/peage/challenge')
      .send({ platform: 'web' })
    const disabled = await request(await serve(app))
      .post('/peage/challenge')
      .send({ platform: PLATFORM_PLAY_INTEGRITY })
    expect([unknown.status, disabled.status]).toStrictEqual([400, 400])
  })

  it('accepts a body of exactly 128 KiB', async () => {
    const { app } = makeApp()
    const response = await request(await serve(app))
      .post('/peage/challenge')
      .set('content-type', 'application/json')
      .send(challengeBodyOfLength(PROTOCOL_MAX_BODY_BYTES))
    expect(response.status).toBe(200)
  })

  it('rejects a body of 128 KiB plus one byte with 413', async () => {
    const { app } = makeApp()
    const response = await request(await serve(app))
      .post('/peage/challenge')
      .set('content-type', 'application/json')
      .send(challengeBodyOfLength(PROTOCOL_MAX_BODY_BYTES + 1))
    expect(response.status).toBe(413)
  })

  it.each([
    ['gzip', gzipSync],
    ['deflate', deflateSync],
    ['br', brotliCompressSync],
  ])(
    'rejects a valid challenge request sent as a %s JSON body with 415',
    async (contentEncoding, compress) => {
      const { app } = makeApp()
      const response = await postEncoded(
        await serve(app),
        '/peage/challenge',
        { 'content-type': 'application/json', 'content-encoding': contentEncoding },
        new Uint8Array(compress(JSON.stringify({ platform: PLATFORM_APP_ATTEST }))),
      )
      expect(response.status).toBe(415)
    },
  )

  it('answers Content-Encoding: gzip with 415 before reading the upload and closes the connection', async () => {
    const { app } = makeApp()
    const upload = await uploadSlowlyOverSocket(await serve(app), '/peage/challenge', {
      'Content-Encoding': 'gzip',
    })
    expect(upload).toStrictEqual({ status: 415, connection: 'close', uploadFinished: false })
  })

  it('accepts Content-Encoding: Identity', async () => {
    const { app } = makeApp()
    const response = await request(await serve(app))
      .post('/peage/challenge')
      .set('content-encoding', 'Identity')
      .send({ platform: PLATFORM_APP_ATTEST })
    expect(response.status).toBe(200)
  })

  it('accepts a chunked body', async () => {
    const { app } = makeApp()
    const status = await statusOverSocket(
      await serve(app),
      requestHead('POST', '/peage/challenge', {
        'Content-Type': 'application/json',
        'Transfer-Encoding': 'chunked',
        Connection: 'close',
      }) + chunkedBody(JSON.stringify({ platform: PLATFORM_APP_ATTEST })),
    )
    expect(status).toBe(200)
  })

  it('answers Transfer-Encoding: gzip, chunked with 501 before reading the body', async () => {
    const { app } = makeApp()
    const status = await statusOverSocket(
      await serve(app),
      requestHead('POST', '/peage/challenge', {
        'Content-Type': 'application/json',
        'Transfer-Encoding': 'gzip, chunked',
      }),
    )
    expect(status).toBe(501)
  })
})

describe('peage.solve', () => {
  it.each([
    ['missing fields', { platform: PLATFORM_APP_ATTEST }],
    [
      'a mistyped field',
      { platform: PLATFORM_APP_ATTEST, challenge: 'A'.repeat(43), keyId: 42, proof: 'AAAA' },
    ],
  ])('rejects %s with 400', async (_case, body) => {
    const { app } = makeApp()
    const response = await request(await serve(app))
      .post('/peage/solve')
      .send(body)
    expect(response.status).toBe(400)
  })

  it('rejects an unknown challenge with 401, no body and the reason in WWW-Authenticate', async () => {
    const { app } = makeApp()
    const response = await request(await serve(app))
      .post('/peage/solve')
      .send({
        platform: PLATFORM_APP_ATTEST,
        challenge: 'A'.repeat(43),
        keyId: KEY_ID,
        proof: 'AAAA',
      })
    expect(response.status).toBe(401)
    expect(response.text).toBe('')
    expect(response.headers['www-authenticate']).toBe('Peage error="unknown_challenge"')
  })

  it('checks the challenge of a 100 KiB solve body instead of rejecting it with 413', async () => {
    const { app } = makeApp()
    const response = await request(await serve(app))
      .post('/peage/solve')
      .send({
        platform: PLATFORM_APP_ATTEST,
        challenge: 'A'.repeat(43),
        keyId: KEY_ID,
        proof: 'A'.repeat(100 * 1024),
      })
    expect(response.status).toBe(401)
    expect(response.headers['www-authenticate']).toBe('Peage error="unknown_challenge"')
  })

  it('answers 204 to an attestation that verifies', async () => {
    const server = await serve(makeAndroidApp())
    const deviceKey = newDeviceKey()
    const { body } = await request(server)
      .post('/peage/challenge')
      .send({ platform: PLATFORM_PLAY_INTEGRITY })
    const response = await request(server)
      .post('/peage/solve')
      .send({
        platform: PLATFORM_PLAY_INTEGRITY,
        challenge: body.challenge,
        keyId: keyIdFor(deviceKey),
        proof: androidProof(body.challenge, deviceKey),
      })
    expect(response.status).toBe(204)
  })

  it('rejects a valid attestation sent as a gzip JSON body with 415', async () => {
    const server = await serve(makeAndroidApp())
    const deviceKey = newDeviceKey()
    const { body } = await request(server)
      .post('/peage/challenge')
      .send({ platform: PLATFORM_PLAY_INTEGRITY })
    const solveBody = JSON.stringify({
      platform: PLATFORM_PLAY_INTEGRITY,
      challenge: body.challenge,
      keyId: keyIdFor(deviceKey),
      proof: androidProof(body.challenge, deviceKey),
    })
    const response = await postEncoded(
      server,
      '/peage/solve',
      { 'content-type': 'application/json', 'content-encoding': 'gzip' },
      gzipText(solveBody),
    )
    expect(response.status).toBe(415)
  })

  it('rejects a valid proof with a space inside with 400', async () => {
    const server = await serve(makeAndroidApp())
    const deviceKey = newDeviceKey()
    const { body } = await request(server)
      .post('/peage/challenge')
      .send({ platform: PLATFORM_PLAY_INTEGRITY })
    const response = await request(server)
      .post('/peage/solve')
      .send({
        platform: PLATFORM_PLAY_INTEGRITY,
        challenge: body.challenge,
        keyId: keyIdFor(deviceKey),
        proof: withSpaceInside(androidProof(body.challenge, deviceKey)),
      })
    expect(response.status).toBe(400)
  })

  // A Play Integrity proof encodes JSON text, whose base64url almost never holds - or _ to re-spell.
  it('rejects a proof holding + and / with 400, leaving its challenge solvable', async () => {
    const server = await serve(makeAndroidApp())
    const deviceKey = newDeviceKey()
    const { body } = await request(server)
      .post('/peage/challenge')
      .send({ platform: PLATFORM_PLAY_INTEGRITY })
    const solveBody = {
      platform: PLATFORM_PLAY_INTEGRITY,
      challenge: body.challenge,
      keyId: keyIdFor(deviceKey),
      proof: androidProof(body.challenge, deviceKey),
    }

    const standardAlphabetResponse = await request(server)
      .post('/peage/solve')
      .send({ ...solveBody, proof: `++//${solveBody.proof}` })
    const validResponse = await request(server).post('/peage/solve').send(solveBody)

    expect(standardAlphabetResponse.status).toBe(400)
    expect(validResponse.status).toBe(204)
  })

  it('rejects an attestation that fails verification with 401 and the reason in WWW-Authenticate', async () => {
    const server = await serve(makeAndroidApp())
    const { body } = await request(server)
      .post('/peage/challenge')
      .send({ platform: PLATFORM_PLAY_INTEGRITY })
    const response = await request(server)
      .post('/peage/solve')
      .send({
        platform: PLATFORM_PLAY_INTEGRITY,
        challenge: body.challenge,
        keyId: keyIdFor(newDeviceKey()),
        proof: androidProof(body.challenge, newDeviceKey()),
      })
    expect(response.status).toBe(401)
    expect(response.headers['www-authenticate']).toBe('Peage error="invalid_attestation"')
  })

  it('answers 500 when the store fails, instead of blaming the client', async () => {
    const failingStore: PeageStore = {
      ...createMemoryStore(),
      async takeChallenge() {
        throw new Error('ECONNREFUSED')
      },
    }
    const { app } = makeApp({ store: failingStore })
    const response = await request(await serve(app))
      .post('/peage/solve')
      .send({
        platform: PLATFORM_APP_ATTEST,
        challenge: 'A'.repeat(43),
        keyId: KEY_ID,
        proof: 'AAAA',
      })
    expect(response.status).toBe(500)
  })

  it('answers an upload the client aborted with 400, without calling the error handler', async () => {
    const { app } = makeApp()
    const errors = recordErrors(app)
    const response = await abortUpload(await serve(app), '/peage/solve')
    expect({ status: response.statusCode, errors }).toStrictEqual({ status: 400, errors: [] })
  })
})

describe('peage.protect', () => {
  it('rejects a request without Péage headers with a bare Peage challenge', async () => {
    const { app } = makeApp()
    const response = await request(await serve(app)).get('/api/hello')
    expect(response.status).toBe(401)
    expect(response.headers['www-authenticate']).toBe('Peage')
  })

  it('rejects an empty keyId header like a missing one', async () => {
    const app = await makeAppWithKey()
    const response = await request(await serve(app))
      .get('/api/hello')
      .set(HTTP_HEADER_KEY_ID, '')
      .set(HTTP_HEADER_ASSERTION, 'AAAA')
    expect(response.status).toBe(401)
    expect(response.headers['www-authenticate']).toBe('Peage')
  })

  it('stops reading the upload of a request without Péage headers and closes the connection after the 401', async () => {
    const { app } = makeApp()
    const upload = await uploadSlowlyOverSocket(await serve(app), '/api/echo', {})
    expect(upload).toStrictEqual({ status: 401, connection: 'close', uploadFinished: false })
  })

  it('keeps the connection alive after a 401 for a request without a body', async () => {
    const { app } = makeApp()
    const response = await fetch(`http://127.0.0.1:${portOf(await serve(app))}/api/hello`)
    expect({
      status: response.status,
      connection: response.headers.get('connection'),
    }).toStrictEqual({
      status: 401,
      connection: 'keep-alive',
    })
  })

  it('closes the connection when a store failure reaches the error handler before the upload finished', async () => {
    const failingStore: PeageStore = {
      ...createMemoryStore(),
      async loadAttestedKey() {
        throw new Error('ECONNREFUSED')
      },
    }
    const { app } = makeApp({ store: failingStore })
    const errors = recordErrors(app)
    const upload = await uploadSlowlyOverSocket(
      await serve(app),
      '/api/echo',
      signedEchoHeaders(''),
    )
    expect({ ...upload, errorCount: errors.length }).toStrictEqual({
      status: 500,
      connection: 'close',
      uploadFinished: false,
      errorCount: 1,
    })
  })

  it('tells the client when its key is unknown', async () => {
    const { app } = makeApp()
    const response = await request(await serve(app))
      .get('/api/hello')
      .set(HTTP_HEADER_KEY_ID, UNKNOWN_KEY_ID)
      .set(HTTP_HEADER_ASSERTION, 'AAAA')
    expect(response.status).toBe(401)
    expect(response.headers['www-authenticate']).toBe('Peage error="unknown_key"')
  })

  it('rejects a streamed body that grows past maxBodyBytes with 413 over a kept-alive connection', async () => {
    const app = await makeAppWithKey({ maxBodyBytes: 32 })
    const response = await uploadInChunks(await serve(app), 3)
    expect(response).toStrictEqual({ status: 413, connection: 'keep-alive' })
  })

  it('cuts off a streamed body that grows past three times maxBodyBytes with 413 and Connection: close', async () => {
    const app = await makeAppWithKey({ maxBodyBytes: 32 })
    const response = await uploadInChunks(await serve(app), 16)
    expect(response).toStrictEqual({ status: 413, connection: 'close' })
  })

  it('delivers the 413 over a kept-alive connection for a body up to three times maxBodyBytes', async () => {
    const maxBodyBytes = 1024 * 1024
    const app = await makeAppWithKey({ maxBodyBytes })
    const server = await serve(app)
    const port = portOf(server)
    const responses: { status: number; connection: string | null }[] = []
    for (let attempt = 0; attempt < 5; attempt++) {
      // oxlint-disable-next-line no-await-in-loop
      const response = await fetch(`http://127.0.0.1:${port}/api/echo`, {
        method: 'POST',
        headers: {
          ...signedEchoHeaders(''),
          'content-type': 'application/octet-stream',
        },
        body: new Uint8Array(2 * maxBodyBytes),
      })
      responses.push({ status: response.status, connection: response.headers.get('connection') })
    }
    expect(responses).toStrictEqual(
      Array.from({ length: 5 }, () => ({ status: 413, connection: 'keep-alive' })),
    )
  })

  it('closes the connection after a 413 for a body declared over three times maxBodyBytes', async () => {
    const app = await makeAppWithKey({ maxBodyBytes: 32 })
    const upload = await uploadSlowlyOverSocket(
      await serve(app),
      '/api/echo',
      signedEchoHeaders(''),
    )
    expect(upload).toStrictEqual({ status: 413, connection: 'close', uploadFinished: false })
  })

  it('answers an upload the client aborted with 400, without calling the error handler', async () => {
    const app = await makeAppWithKey()
    const errors = recordErrors(app)
    const response = await abortUpload(await serve(app), '/api/echo')
    expect({ status: response.statusCode, errors }).toStrictEqual({ status: 400, errors: [] })
  })

  it('accepts a signed body of exactly maxBodyBytes', async () => {
    const app = await makeAppWithKey({ maxBodyBytes: 32 })
    const body = 'x'.repeat(32)
    const response = await request(await serve(app))
      .post('/api/echo')
      .set(signedEchoHeaders(body))
      .set('content-type', 'application/octet-stream')
      .send(body)
    expect(response.status).toBe(200)
  })

  it('delivers the 413 over a kept-alive connection for a body of exactly three times maxBodyBytes', async () => {
    const maxBodyBytes = 32
    const app = await makeAppWithKey({ maxBodyBytes })
    const response = await fetch(`http://127.0.0.1:${portOf(await serve(app))}/api/echo`, {
      method: 'POST',
      headers: {
        ...signedEchoHeaders(''),
        'content-type': 'application/octet-stream',
      },
      body: new Uint8Array(3 * maxBodyBytes),
    })
    expect({
      status: response.status,
      connection: response.headers.get('connection'),
    }).toStrictEqual({
      status: 413,
      connection: 'keep-alive',
    })
  })

  it('rejects a body larger than maxBodyBytes with 413', async () => {
    const app = await makeAppWithKey({ maxBodyBytes: 32 })
    const response = await request(await serve(app))
      .post('/api/echo')
      .set(signedEchoHeaders(''))
      .set('content-type', 'application/octet-stream')
      .send(Buffer.alloc(64))
    expect(response.status).toBe(413)
  })

  it('accepts a signed body of exactly 1 MiB when maxBodyBytes is not set', async () => {
    const app = await makeAppWithKey()
    const body = 'x'.repeat(DEFAULT_MAX_BODY_BYTES)
    const response = await request(await serve(app))
      .post('/api/echo')
      .set(signedEchoHeaders(body))
      .set('content-type', 'application/octet-stream')
      .send(body)
    expect(response.status).toBe(200)
  })

  it('rejects a signed body of 1 MiB plus one byte with 413 when maxBodyBytes is not set', async () => {
    const app = await makeAppWithKey()
    const body = 'x'.repeat(DEFAULT_MAX_BODY_BYTES + 1)
    const response = await request(await serve(app))
      .post('/api/echo')
      .set(signedEchoHeaders(body))
      .set('content-type', 'application/octet-stream')
      .send(body)
    expect(response.status).toBe(413)
  })

  it.each([
    [
      'an assertion that is not base64url',
      { [HTTP_HEADER_KEY_ID]: KEY_ID, [HTTP_HEADER_ASSERTION]: '!!!' },
    ],
    ['a truncated assertion', { [HTTP_HEADER_KEY_ID]: KEY_ID, [HTTP_HEADER_ASSERTION]: 'A' }],
    ['a non-canonical keyId', { [HTTP_HEADER_KEY_ID]: 'abc', [HTTP_HEADER_ASSERTION]: 'AAAA' }],
  ])('rejects %s with 400 and no WWW-Authenticate', async (_case, headers) => {
    const app = await makeAppWithKey()
    const response = await request(await serve(app))
      .get('/api/hello')
      .set(headers)
    expect(response.status).toBe(400)
    expect(response.headers['www-authenticate']).toBeUndefined()
  })

  it('rejects a valid assertion spelled with + and / instead of - and _, unpadded, with 400', async () => {
    const app = await makeAppWithKey()
    const assertion = encodedHelloAssertionWhere((encoded) => /[-_]/.test(encoded))
    const response = await request(await serve(app))
      .get('/api/hello')
      .set(HTTP_HEADER_KEY_ID, KEY_ID)
      .set(HTTP_HEADER_ASSERTION, inStandardAlphabet(assertion))
    expect(response.status).toBe(400)
  })

  it.each(['=', '=='])(
    'rejects a valid base64url assertion padded with %s with 400',
    async (padding) => {
      const app = await makeAppWithKey()
      const assertion = encodedHelloAssertionWhere(
        (encoded) => (encoded.length + padding.length) % 4 === 0,
      )
      const response = await request(await serve(app))
        .get('/api/hello')
        .set(HTTP_HEADER_KEY_ID, KEY_ID)
        .set(HTTP_HEADER_ASSERTION, assertion + padding)
      expect(response.status).toBe(400)
    },
  )

  it('rejects a valid assertion with a space inside with 400', async () => {
    const app = await makeAppWithKey()
    const assertion = signedAssertion({ method: 'GET', path: '/api/hello', body: '' })
    const response = await request(await serve(app))
      .get('/api/hello')
      .set(HTTP_HEADER_KEY_ID, KEY_ID)
      .set(HTTP_HEADER_ASSERTION, withSpaceInside(toBase64url(assertion)))
    expect(response.status).toBe(400)
  })

  it('rejects a signed JSON request whose body is not JSON with 400', async () => {
    const app = await makeAppWithKey()
    const body = '{not json'
    const response = await request(await serve(app))
      .post('/api/echo')
      .set(signedEchoHeaders(body))
      .set('content-type', 'application/json')
      .send(body)
    expect(response.status).toBe(400)
  })

  it('lets a signed empty JSON request through', async () => {
    const app = await makeAppWithKey()
    const response = await request(await serve(app))
      .post('/api/echo')
      .set(signedEchoHeaders(''))
      .set('content-type', 'application/json')
    expect(response.status).toBe(200)
  })

  it('lets a signed request through and exposes the verified device', async () => {
    const app = await makeAppWithKey()
    const response = await request(await serve(app))
      .get('/api/hello')
      .set(signedHeaders({ method: 'GET', path: '/api/hello', body: '' }))
    expect(response.status).toBe(200)
    expect(response.body.peage).toMatchObject({ keyId: KEY_ID, platform: PLATFORM_APP_ATTEST })
  })

  it('verifies the path as the client sent it, including the router mount path', async () => {
    const app = await makeAppWithKey()
    const response = await request(await serve(app))
      .get('/v1/hello')
      .set(signedHeaders({ method: 'GET', path: '/v1/hello', body: '' }))
    expect(response.status).toBe(200)
  })

  it('parses a signed JSON body, including +json types, for downstream handlers', async () => {
    const app = await makeAppWithKey()
    const bodyText = JSON.stringify({ hello: 'world' })
    for (const contentType of ['application/json', 'application/problem+json']) {
      // oxlint-disable-next-line no-await-in-loop
      const response = await request(await serve(app))
        .post('/api/echo')
        .set(signedEchoHeaders(bodyText))
        .set('content-type', contentType)
        .send(bodyText)
      expect(response.body).toStrictEqual({ received: { hello: 'world' } })
    }
  })

  it('rejects a body tampered with after signing', async () => {
    const app = await makeAppWithKey()
    const response = await request(await serve(app))
      .post('/api/echo')
      .set(signedEchoHeaders('{"hello":"world"}'))
      .set('content-type', 'application/json')
      .send('{"hello":"tampered"}')
    expect(response.status).toBe(401)
    expect(response.headers['www-authenticate']).toBe('Peage error="invalid_signature"')
  })

  it('fails closed when a body parser read the body before protect', async () => {
    const app = await makeAppWithKey({ readBodyFirst: express.json() })
    const response = await request(await serve(app))
      .post('/api/echo')
      .set(signedEchoHeaders(''))
      .set('content-type', 'application/json')
      .send('{"to":"attacker","amount":1000000}')
    expect(response.status).toBe(500)
  })

  it('fails closed when a middleware consumed the body stream before protect', async () => {
    const app = await makeAppWithKey({ readBodyFirst: consumeBodyStream })
    const response = await request(await serve(app))
      .post('/api/echo')
      .set(signedEchoHeaders(''))
      .set('content-type', 'application/json')
      .send('{"to":"attacker","amount":1000000}')
    expect(response.status).toBe(500)
  })

  it('fails closed when a middleware set req.body before protect', async () => {
    const app = await makeAppWithKey({ readBodyFirst: setBodyWithoutReading })
    const response = await request(await serve(app))
      .post('/api/echo')
      .set(signedEchoHeaders(''))
    expect(response.status).toBe(500)
  })

  it.each([
    ['gzip', gzipSync],
    ['deflate', deflateSync],
  ])(
    'verifies a %s JSON body signed over its uncompressed bytes and parses it',
    async (contentEncoding, compress) => {
      const app = await makeAppWithKey()
      const bodyText = JSON.stringify({ hello: 'world' })
      const response = await postEncoded(
        await serve(app),
        '/api/echo',
        {
          ...signedEchoHeaders(bodyText),
          'content-type': 'application/json',
          'content-encoding': contentEncoding,
        },
        new Uint8Array(compress(bodyText)),
      )
      expect(response.status).toBe(200)
      expect(await response.json()).toStrictEqual({ received: { hello: 'world' } })
    },
  )

  it.each([
    [
      'gzip',
      'other bytes',
      concatBytes(gzipText('{"hello":"world"}'), new TextEncoder().encode('JUNK')),
    ],
    ['gzip', 'a zero byte', concatBytes(gzipText('{"hello":"world"}'), Uint8Array.of(0))],
    [
      'deflate',
      'other bytes',
      concatBytes(
        new Uint8Array(deflateSync('{"hello":"world"}')),
        new TextEncoder().encode('JUNK'),
      ),
    ],
  ])('rejects %s followed by %s with 400', async (contentEncoding, _trailer, body) => {
    const app = await makeAppWithKey()
    const response = await postEncoded(
      await serve(app),
      '/api/echo',
      {
        ...signedEchoHeaders('{"hello":"world"}'),
        'content-type': 'application/json',
        'content-encoding': contentEncoding,
      },
      body,
    )
    expect(response.status).toBe(400)
  })

  it('decodes a gzip body of several members in order', async () => {
    const app = await makeAppWithKey()
    const response = await postEncoded(
      await serve(app),
      '/api/echo',
      {
        ...signedEchoHeaders('{"hello":"world"}'),
        'content-type': 'application/json',
        'content-encoding': 'gzip',
      },
      concatBytes(gzipText('{"hello":'), gzipText('"world"}')),
    )
    expect(response.status).toBe(200)
    expect(await response.json()).toStrictEqual({ received: { hello: 'world' } })
  })

  it('answers an unknown key with a gzip body that decodes past the limit with 401', async () => {
    const { app } = makeApp({ maxBodyBytes: 1024 })
    const response = await postEncoded(
      await serve(app),
      '/api/echo',
      {
        [HTTP_HEADER_KEY_ID]: UNKNOWN_KEY_ID,
        [HTTP_HEADER_ASSERTION]: 'AAAA',
        'content-type': 'application/json',
        'content-encoding': 'gzip',
      },
      new Uint8Array(gzipSync(new Uint8Array(1024 * 1024))),
    )
    expect(response.status).toBe(401)
    expect(response.headers.get('www-authenticate')).toBe('Peage error="unknown_key"')
  })

  it.each([
    ['Content-Encoding: br', { 'Content-Encoding': 'br', 'Content-Length': '4' }, 'JUNK'],
    ['Transfer-Encoding: gzip, chunked', { 'Transfer-Encoding': 'gzip, chunked' }, ''],
  ])('answers an unknown key under %s with 401', async (_case, codingHeaders, body) => {
    const { app } = makeApp()
    const status = await statusOverSocket(
      await serve(app),
      requestHead('POST', '/api/echo', {
        [HTTP_HEADER_KEY_ID]: UNKNOWN_KEY_ID,
        [HTTP_HEADER_ASSERTION]: 'AAAA',
        'Content-Type': 'application/octet-stream',
        Connection: 'close',
        ...codingHeaders,
      }) + body,
    )
    expect(status).toBe(401)
  })

  it('rejects a gzip body signed over its compressed bytes with 401 invalid_signature', async () => {
    const app = await makeAppWithKey()
    const compressed = gzipText(JSON.stringify({ hello: 'world' }))
    const response = await postEncoded(
      await serve(app),
      '/api/echo',
      {
        ...signedEchoHeaders(compressed),
        'content-type': 'application/json',
        'content-encoding': 'gzip',
      },
      compressed,
    )
    expect(response.status).toBe(401)
    expect(response.headers.get('www-authenticate')).toBe('Peage error="invalid_signature"')
  })

  it.each(['br', 'zstd', 'gzip, br'])(
    'rejects Content-Encoding %s with 415, even when signed over the bytes sent',
    async (contentEncoding) => {
      const app = await makeAppWithKey()
      const body = 'plain bytes'
      const response = await request(await serve(app))
        .post('/api/echo')
        .set(signedEchoHeaders(body))
        .set('content-type', 'application/octet-stream')
        .set('content-encoding', contentEncoding)
        .send(body)
      expect(response.status).toBe(415)
    },
  )

  it('answers an unsupported Content-Encoding with 415 before reading the upload and closes the connection', async () => {
    const app = await makeAppWithKey()
    const upload = await uploadSlowlyOverSocket(await serve(app), '/api/echo', {
      ...signedEchoHeaders(''),
      'Content-Encoding': 'zstd',
    })
    expect(upload).toStrictEqual({ status: 415, connection: 'close', uploadFinished: false })
  })

  it('rejects an empty body under an unsupported Content-Encoding with 415', async () => {
    const app = await makeAppWithKey()
    const response = await request(await serve(app))
      .post('/api/echo')
      .set(signedEchoHeaders(''))
      .set('content-type', 'application/octet-stream')
      .set('content-encoding', 'br')
    expect(response.status).toBe(415)
  })

  it('verifies a gzip body under Content-Encoding: GZIP', async () => {
    const app = await makeAppWithKey()
    const bodyText = JSON.stringify({ hello: 'world' })
    const response = await postEncoded(
      await serve(app),
      '/api/echo',
      {
        ...signedEchoHeaders(bodyText),
        'content-type': 'application/json',
        'content-encoding': 'GZIP',
      },
      gzipText(bodyText),
    )
    expect(response.status).toBe(200)
    expect(await response.json()).toStrictEqual({ received: { hello: 'world' } })
  })

  it('verifies a body under Content-Encoding: identity', async () => {
    const app = await makeAppWithKey()
    const bodyText = JSON.stringify({ hello: 'world' })
    const response = await request(await serve(app))
      .post('/api/echo')
      .set(signedEchoHeaders(bodyText))
      .set('content-type', 'application/json')
      .set('content-encoding', 'identity')
      .send(bodyText)
    expect(response.status).toBe(200)
  })

  it('verifies a chunked body', async () => {
    const app = await makeAppWithKey()
    const bodyText = JSON.stringify({ hello: 'world' })
    const status = await statusOverSocket(
      await serve(app),
      requestHead('POST', '/api/echo', {
        ...signedEchoHeaders(bodyText),
        'Content-Type': 'application/json',
        'Transfer-Encoding': 'chunked',
        Connection: 'close',
      }) + chunkedBody(bodyText),
    )
    expect(status).toBe(200)
  })

  it('answers Transfer-Encoding: gzip, chunked with 501 before reading the body', async () => {
    const app = await makeAppWithKey()
    const status = await statusOverSocket(
      await serve(app),
      requestHead('POST', '/api/echo', {
        ...signedEchoHeaders(''),
        'Content-Type': 'application/octet-stream',
        'Transfer-Encoding': 'gzip, chunked',
      }),
    )
    expect(status).toBe(501)
  })

  it('accepts a gzip body that inflates to exactly maxBodyBytes', async () => {
    const app = await makeAppWithKey({ maxBodyBytes: 32 })
    const body = 'x'.repeat(32)
    const response = await postEncoded(
      await serve(app),
      '/api/echo',
      {
        ...signedEchoHeaders(body),
        'content-type': 'application/octet-stream',
        'content-encoding': 'gzip',
      },
      gzipText(body),
    )
    expect(response.status).toBe(200)
  })

  it('rejects a gzip body that inflates to maxBodyBytes plus one byte with 413', async () => {
    const app = await makeAppWithKey({ maxBodyBytes: 32 })
    const body = 'x'.repeat(33)
    const response = await postEncoded(
      await serve(app),
      '/api/echo',
      {
        ...signedEchoHeaders(body),
        'content-type': 'application/octet-stream',
        'content-encoding': 'gzip',
      },
      gzipText(body),
    )
    expect(response.status).toBe(413)
  })

  it('rejects a gzip body under maxBodyBytes that inflates past it with 413', async () => {
    const maxBodyBytes = 1024
    const app = await makeAppWithKey({ maxBodyBytes })
    const inflated = 'x'.repeat(512 * maxBodyBytes)
    const compressed = gzipText(inflated)
    expect(compressed.length).toBeLessThanOrEqual(maxBodyBytes)
    const response = await postEncoded(
      await serve(app),
      '/api/echo',
      {
        ...signedEchoHeaders(inflated),
        'content-type': 'application/octet-stream',
        'content-encoding': 'gzip',
      },
      compressed,
    )
    expect(response.status).toBe(413)
  })

  it('lets an empty body under Content-Encoding: gzip through as empty', async () => {
    const app = await makeAppWithKey()
    const response = await request(await serve(app))
      .post('/api/echo')
      .set(signedEchoHeaders(''))
      .set('content-type', 'application/octet-stream')
      .set('content-encoding', 'gzip')
    expect(response.status).toBe(200)
  })

  it('rejects a body that is not valid gzip under Content-Encoding: gzip with 400', async () => {
    const app = await makeAppWithKey()
    const body = 'not gzip'
    const response = await request(await serve(app))
      .post('/api/echo')
      .set(signedEchoHeaders(body))
      .set('content-type', 'application/octet-stream')
      .set('content-encoding', 'gzip')
      .send(body)
    expect(response.status).toBe(400)
  })

  it.each([
    ['/api/hello', '/api/hello'],
    ['/api/hello?x=1', '/api/hello?x=1'],
    ['', '/'],
    ['?x=1', '/?x=1'],
  ])(
    'verifies the absolute-form target http://host%s signed over %s',
    async (pathAndQuery, signedPath) => {
      const app = await makeAppWithKey()
      const server = await serve(app)
      const status = await statusOverSocket(
        server,
        requestHead('GET', `http://127.0.0.1:${portOf(server)}${pathAndQuery}`, {
          ...signedHeaders({ method: 'GET', path: signedPath, body: '' }),
          Connection: 'close',
        }),
      )
      expect(status).toBe(200)
    },
  )

  it.each(['HTTP://127.0.0.1', 'https://127.0.0.1', 'http://[::1]:8080', 'http://api.example.com'])(
    'verifies the absolute-form target %s/api/hello signed over /api/hello',
    async (schemeAndAuthority) => {
      const app = await makeAppWithKey()
      const server = await serve(app)
      const status = await statusOverSocket(
        server,
        requestHead('GET', `${schemeAndAuthority}/api/hello`, {
          ...signedHeaders({ method: 'GET', path: '/api/hello', body: '' }),
          Connection: 'close',
        }),
      )
      expect(status).toBe(200)
    },
  )

  it.each([
    'http://h:x',
    'http://user@127.0.0.1',
    'http://h%41',
    'http://h;x',
    "http://h'x",
    'http://',
    'ftp://127.0.0.1',
  ])(
    'rejects the absolute-form target %s/hello with 400, even when signed over /hello',
    async (schemeAndAuthority) => {
      const app = await makeAppWithKey()
      const server = await serve(app)
      const status = await statusOverSocket(
        server,
        requestHead('GET', `${schemeAndAuthority}/hello`, {
          ...signedHeaders({ method: 'GET', path: '/hello', body: '' }),
          Connection: 'close',
        }),
      )
      expect(status).toBe(400)
    },
  )

  it.each(['/a%2Fb%c3%A9', "/a'b;c:d@e", '/a!$&()*+,=-._~', '/api/hello?x=1&y=%20&z=/?'])(
    'verifies the request-target %s signed over it',
    async (target) => {
      const app = await makeAppWithKey()
      const status = await statusOverSocket(
        await serve(app),
        requestHead('GET', target, {
          ...signedHeaders({ method: 'GET', path: target, body: '' }),
          Connection: 'close',
        }),
      )
      expect(status).toBe(200)
    },
  )

  it('verifies the request-target * of OPTIONS signed over it', async () => {
    const app = await makeAppWithKey()
    const status = await statusOverSocket(
      await serve(app),
      requestHead('OPTIONS', '*', {
        ...signedHeaders({ method: 'OPTIONS', path: '*', body: '' }),
        Connection: 'close',
      }),
    )
    expect(status).toBe(200)
  })
})

describe('verifiedRequestOf', () => {
  async function makeVerifiedRequestApp() {
    const store = createMemoryStore()
    await registerTestKey(store)
    const peage = createPeage({ appAttest: { appId: APP_ID, environment: 'development' }, store })
    const app = express()
    app.get('/api/hello', peage.protect, (_req, res) => {
      res.json(verifiedRequestOf(res))
    })
    app.get('/api/unprotected', (_req, res) => {
      res.json(verifiedRequestOf(res))
    })
    const errors = recordErrors(app)
    return { app, errors }
  }

  it('returns the request protect verified', async () => {
    const { app } = await makeVerifiedRequestApp()
    const response = await request(await serve(app))
      .get('/api/hello')
      .set(signedHeaders({ method: 'GET', path: '/api/hello', body: '' }))
    expect(response.status).toBe(200)
    expect(response.body).toMatchObject({ keyId: KEY_ID, platform: PLATFORM_APP_ATTEST })
  })

  it('throws in a handler that protect did not run before, which answers 500', async () => {
    const { app, errors } = await makeVerifiedRequestApp()
    const response = await request(await serve(app)).get('/api/unprotected')
    expect(response.status).toBe(500)
    expect(errors).toStrictEqual([new Error('Péage protect must run before this handler')])
  })
})
