import { createPeage, type LoadRevokedSerialNumbers } from '@peage/express'
import {
  HTTP_HEADER_KEY_ID,
  parseAuthenticateError,
  PLATFORM_PLAY_INTEGRITY,
} from '@peage/protocol'
import { createPeageClientWithNative, PeageClientError } from '@peage/react-native/testing'
import { createMemoryStore } from '@peage/store-memory'
import {
  createKeyAttestationRoot,
  createPlayIntegrityKeys,
  keyIdFor,
  newDeviceKey,
} from '@peage/tests'
import express from 'express'
import { afterEach, describe, expect, it } from 'vitest'

import { createNodePlayIntegrityAttest } from '../nodeNativeAttest.ts'
import { closeServers, serve } from '../servers.ts'

const PACKAGE_NAME = 'dev.peage.conformance'
const keys = createPlayIntegrityKeys()
const keyAttestationRoot = createKeyAttestationRoot()

async function startServer(
  loadRevokedSerialNumbers: LoadRevokedSerialNumbers = async () => new Set(),
) {
  const store = createMemoryStore()
  const peage = createPeage({
    playIntegrity: {
      packageName: PACKAGE_NAME,
      decryptionKey: keys.decryptionKey,
      verificationKey: keys.verificationKey,
      keyAttestation: {
        trustedRoots: [keyAttestationRoot.certificate.toString()],
        loadRevokedSerialNumbers,
      },
    },
    store,
  })

  const app = express()
  app.post('/peage/challenge', peage.challenge)
  app.post('/peage/solve', peage.solve)
  app.get('/api/hello', peage.protect, (_req, res) => {
    res.json({ ok: true })
  })
  app.post('/api/echo', peage.protect, (req, res) => {
    res.json({ received: req.body })
  })

  const baseUrl = await serve(app)
  return { store, baseUrl }
}

afterEach(closeServers)

async function startClientAndServer(
  options: {
    verdict?: Parameters<typeof createNodePlayIntegrityAttest>[0]['verdict']
    loadRevokedSerialNumbers?: LoadRevokedSerialNumbers
  } = {},
) {
  const { store, baseUrl } = await startServer(options.loadRevokedSerialNumbers)
  const { native } = createNodePlayIntegrityAttest({
    keys,
    keyAttestationRoot,
    packageName: PACKAGE_NAME,
    verdict: options.verdict,
  })
  const client = createPeageClientWithNative({ baseUrl, native, platform: PLATFORM_PLAY_INTEGRITY })
  return { store, baseUrl, client, native }
}

describe('react-native client ↔ express round-trip (Play Integrity)', () => {
  it('registers over HTTP and stores the key as a Play Integrity key', async () => {
    const { store, baseUrl, client, native } = await startClientAndServer()
    const keyId = await client.register()

    expect(await native.getKeyId(baseUrl)).toBe(keyId)
    expect((await store.loadAttestedKey({ keyId: keyId }))?.platform).toBe(PLATFORM_PLAY_INTEGRITY)
  })

  it('verifies a signed GET after registering', async () => {
    const { client } = await startClientAndServer()
    const response = await client.fetch('/api/hello')
    expect(response.status).toBe(200)
    expect(await response.json()).toStrictEqual({ ok: true })
  })

  it('signs and sends a JSON POST through the client fetch', async () => {
    const { client } = await startClientAndServer()
    const response = await client.fetch('/api/echo', {
      method: 'POST',
      body: JSON.stringify({ hello: 'world' }),
      headers: { 'content-type': 'application/json' },
    })
    expect(response.status).toBe(200)
    expect(await response.json()).toStrictEqual({ received: { hello: 'world' } })
  })

  it('rejects the same route without Péage headers', async () => {
    const { baseUrl } = await startClientAndServer()
    const response = await fetch(`${baseUrl}/api/hello`)
    expect(response.status).toBe(401)
  })

  it('refuses to register a device that fails device integrity', async () => {
    const { baseUrl, client, native } = await startClientAndServer({
      verdict: { deviceRecognitionVerdict: ['MEETS_BASIC_INTEGRITY'] },
    })
    await expect(client.register()).rejects.toSatisfy(
      (error) => error instanceof PeageClientError && error.code === 'ATTESTATION_REJECTED',
    )
    expect(await native.getKeyId(baseUrl)).toBeNull()
  })

  it('registers again when the server has lost the key', async () => {
    const { baseUrl, client, native } = await startClientAndServer()
    const firstKeyId = await client.register()

    const freshServer = await startServer()
    const clientOfFreshServer = createPeageClientWithNative({
      baseUrl: freshServer.baseUrl,
      keyScope: baseUrl,
      native,
      platform: PLATFORM_PLAY_INTEGRITY,
    })

    const response = await clientOfFreshServer.fetch('/api/hello')

    expect(response.status).toBe(200)
    expect(await native.getKeyId(baseUrl)).not.toBe(firstKeyId)
  })

  it("registers a new key once the server has loaded the list revoking the current one's chain", async () => {
    const revoked = new Set<string>()
    const { store, baseUrl, client, native } = await startClientAndServer({
      loadRevokedSerialNumbers: async () => new Set(revoked),
    })
    const firstKeyId = await client.register()
    const record = await store.loadAttestedKey({ keyId: firstKeyId })
    const intermediateSerial = record?.attestationCertificateSerialNumbers?.[1]
    if (!intermediateSerial) {
      throw new Error('the Android key record has no attestation serial numbers')
    }
    revoked.add(intermediateSerial)

    const beforeTheNewListLoads = await client.fetch('/api/hello')
    expect(beforeTheNewListLoads.status).toBe(200)
    expect(await native.getKeyId(baseUrl)).toBe(firstKeyId)

    const afterTheNewListLoads = await client.fetch('/api/hello')
    expect(afterTheNewListLoads.status).toBe(200)
    expect(await native.getKeyId(baseUrl)).not.toBe(firstKeyId)
  })

  it('keeps verifying signed requests while the revocation list is unavailable', async () => {
    let isGoogleReachable = true
    const { client } = await startClientAndServer({
      loadRevokedSerialNumbers: async () => {
        if (!isGoogleReachable) {
          throw new Error('Key attestation revocation list is unavailable')
        }
        return new Set()
      },
    })
    await client.register()
    isGoogleReachable = false

    const response = await client.fetch('/api/hello')

    expect(response.status).toBe(200)
  })

  it('rejects a signed request whose keyId was never registered', async () => {
    const { baseUrl, native } = await startClientAndServer()
    const sentHeaders: Headers[] = []
    const recordingClient = createPeageClientWithNative({
      baseUrl,
      native,
      platform: PLATFORM_PLAY_INTEGRITY,
      fetch: (input, init = {}) => {
        sentHeaders.push(new Headers(init.headers))
        return fetch(input, init)
      },
    })
    await recordingClient.fetch('/api/hello')
    const headers = new Headers(sentHeaders.at(-1))
    headers.set(HTTP_HEADER_KEY_ID, keyIdFor(newDeviceKey()))

    const response = await fetch(`${baseUrl}/api/hello`, { headers })
    expect(response.status).toBe(401)
    expect(parseAuthenticateError(response.headers.get('WWW-Authenticate'))).toBe('unknown_key')
  })
})
