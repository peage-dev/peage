import { createPeage, verifiedRequestOf } from '@peage/express'
import { PLATFORM_PLAY_INTEGRITY, parseAuthenticateError } from '@peage/protocol'
import { createPeageClientWithNative, type NativeAttest } from '@peage/react-native/testing'
import { createMemoryStore } from '@peage/store-memory'
import { createKeyAttestationRoot, createPlayIntegrityKeys } from '@peage/tests'
import express from 'express'
import { afterEach, describe, expect, it } from 'vitest'

import { createNodePlayIntegrityAttest } from '../nodeNativeAttest.ts'
import { closeServers, serve } from '../servers.ts'

const PACKAGE_NAME = 'dev.peage.conformance'
const DEBUG_TOKEN = 'conformance-debug-token-0123456789'
const keys = createPlayIntegrityKeys()
const keyAttestationRoot = createKeyAttestationRoot()

async function startServer(): Promise<string> {
  const peage = createPeage({
    playIntegrity: {
      packageName: PACKAGE_NAME,
      decryptionKey: keys.decryptionKey,
      verificationKey: keys.verificationKey,
      allowUnrecognizedApps: true,
      keyAttestation: {
        trustedRoots: [keyAttestationRoot.certificate.toString()],
        loadRevokedSerialNumbers: async () => new Set(),
      },
    },
    debugToken: DEBUG_TOKEN,
    store: createMemoryStore(),
  })

  const app = express()
  app.use(peage.router)
  app.post('/api/echo', peage.protect, (_req, res) => {
    const verified = verifiedRequestOf(res)
    res.json({
      debug: verified.debug,
      keyId: verified.debug ? null : verified.keyId,
      body: new TextDecoder().decode(verified.body),
    })
  })
  return serve(app)
}

afterEach(closeServers)

function supportedNative(): NativeAttest {
  return createNodePlayIntegrityAttest({ keys, keyAttestationRoot, packageName: PACKAGE_NAME })
    .native
}

function unsupportedNative(): NativeAttest {
  return { ...supportedNative(), isSupported: async () => false }
}

async function startClientAndServer(native: NativeAttest, debugToken: string) {
  const baseUrl = await startServer()
  const client = createPeageClientWithNative({
    baseUrl,
    debugToken,
    native,
    platform: PLATFORM_PLAY_INTEGRITY,
  })
  return { client, baseUrl }
}

function postJson(body: string): RequestInit {
  return { method: 'POST', headers: { 'content-type': 'application/json' }, body }
}

describe('react-native client ↔ express round-trip (debug token)', () => {
  it.each([
    ['can', supportedNative],
    ['cannot', unsupportedNative],
  ])(
    'sends the debug token from a device that %s attest, and the body reaches the route',
    async (_canAttest, createNative) => {
      const { client } = await startClientAndServer(createNative(), DEBUG_TOKEN)
      const response = await client.fetch('/api/echo', postJson('{"hello":"world"}'))

      expect(response.status).toBe(200)
      expect(await response.json()).toStrictEqual({
        debug: true,
        keyId: null,
        body: '{"hello":"world"}',
      })
    },
  )

  it('rejects another debug token as an invalid signature', async () => {
    const { client } = await startClientAndServer(supportedNative(), `${DEBUG_TOKEN}x`)
    const response = await client.fetch('/api/echo', postJson('{"hello":"world"}'))
    expect(response.status).toBe(401)
    expect(parseAuthenticateError(response.headers.get('WWW-Authenticate'))).toBe(
      'invalid_signature',
    )
  })
})
