import {
  type Platform,
  PLATFORM_APP_ATTEST,
  PLATFORM_PLAY_INTEGRITY,
  toBase64,
} from '@peage/protocol'
import {
  createKeyAttestationRoot,
  createPlayIntegrityKeys,
  flipLastByte,
  keyIdFor,
  newDeviceKey,
  playIntegrityRegistrationProof,
  signPlayIntegrityRequest,
} from '@peage/tests'
import { type KeyObject, generateKeyPairSync } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type {
  AppAttestConfig,
  AttestedKeyRecord,
  IssuedChallenge,
  PeageEvent,
  PeageStore,
} from '../types.ts'

import { CHALLENGE_TTL_MS } from '../challenges.ts'
import { PeageError } from '../errors.ts'
import { createPeage } from '../index.ts'
import {
  IOS_27_ASSERTION,
  IOS_27_ATTESTATION,
  IOS_27_DEVICE,
} from '../verifiers/ios/__tests__/deviceFixtures.ts'

const PACKAGE_NAME = 'dev.peage.core'
const UNISSUED_CHALLENGE = 'A'.repeat(43)
const playIntegrityKeys = createPlayIntegrityKeys()
const keyAttestationRoot = createKeyAttestationRoot()
const PLAY_INTEGRITY_CONFIG = {
  packageName: PACKAGE_NAME,
  decryptionKey: playIntegrityKeys.decryptionKey,
  verificationKey: playIntegrityKeys.verificationKey,
  keyAttestation: {
    trustedRoots: [keyAttestationRoot.certificate.toString()],
    loadRevokedSerialNumbers: async () => new Set<string>(),
  },
}
const APP_ATTEST_CONFIG: AppAttestConfig = {
  appId: IOS_27_DEVICE.appId,
  environment: 'development',
}

function createTestStore() {
  const challenges = new Map<string, IssuedChallenge>()
  const keys = new Map<string, AttestedKeyRecord>()
  const store: PeageStore = {
    async saveChallenge(challenge) {
      challenges.set(`${challenge.platform}:${challenge.value}`, challenge)
    },
    async takeChallenge({ value, platform }) {
      const issued = challenges.get(`${platform}:${value}`) ?? null
      challenges.delete(`${platform}:${value}`)
      return issued
    },
    async saveAttestedKey(record) {
      keys.set(record.keyId, record)
    },
    async loadAttestedKey({ keyId }) {
      return keys.get(keyId) ?? null
    },
  }
  return { store, keys }
}

function createAndroidPeage() {
  const events: PeageEvent[] = []
  const { store, keys } = createTestStore()
  const peage = createPeage({
    playIntegrity: PLAY_INTEGRITY_CONFIG,
    store,
    onEvent: (event) => events.push(event),
  })
  return { peage, keys, events }
}

function createIosPeage() {
  const { store, keys } = createTestStore()
  const peage = createPeage({ appAttest: APP_ATTEST_CONFIG, store })
  return { peage, store, keys }
}

function androidRegistration(challenge: string, deviceKey: KeyObject) {
  return {
    challenge,
    keyId: keyIdFor(deviceKey),
    platform: PLATFORM_PLAY_INTEGRITY,
    proof: playIntegrityRegistrationProof({
      challenge,
      deviceKey,
      packageName: PACKAGE_NAME,
      keys: playIntegrityKeys,
      keyAttestationRoot,
    }),
  }
}

async function expectPeageError(promise: Promise<unknown>, code: string) {
  await expect(promise).rejects.toSatisfy(
    (error) => error instanceof PeageError && error.code === code,
  )
}

async function readEmptyBody(): Promise<Uint8Array> {
  return new Uint8Array()
}

afterEach(() => {
  vi.useRealTimers()
})

describe('createPeage', () => {
  it('refuses a config with no platform', () => {
    // @ts-expect-error The type already forbids this; the runtime guard is for JavaScript callers.
    expect(() => createPeage({ store: createTestStore().store })).toThrow(
      /appAttest, playIntegrity, or both/,
    )
  })

  it('refuses a Play Integrity decryption key of the wrong length', () => {
    const playIntegrity = { ...PLAY_INTEGRITY_CONFIG, decryptionKey: toBase64(new Uint8Array(16)) }
    expect(() => createPeage({ playIntegrity, store: createTestStore().store })).toThrow(/AES-256/)
  })

  it('refuses a Play Integrity verification key that is not P-256', () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' })
    const verificationKey = toBase64(publicKey.export({ format: 'der', type: 'spki' }))
    const playIntegrity = { ...PLAY_INTEGRITY_CONFIG, verificationKey }
    expect(() => createPeage({ playIntegrity, store: createTestStore().store })).toThrow(/P-256/)
  })

  it('refuses an App Attest appId that is not "<Team ID>.<bundle identifier>"', () => {
    for (const appId of ['', 'dev.peage.app', 'abcde12345.dev.peage.app']) {
      expect(() => createPeage({ appAttest: { appId }, store: createTestStore().store })).toThrow(
        /Team ID/,
      )
    }
  })

  it("refuses an App Attest environment other than 'production' or 'development'", () => {
    expect(() =>
      createPeage({
        // @ts-expect-error The type already forbids this; the runtime guard is for JavaScript callers.
        appAttest: { appId: IOS_27_DEVICE.appId, environment: 'staging' },
        store: createTestStore().store,
      }),
    ).toThrow(/'production' or 'development'/)
  })

  it('reports which platforms are enabled', () => {
    const { peage } = createAndroidPeage()
    expect(peage.isPlatformEnabled(PLATFORM_PLAY_INTEGRITY)).toBe(true)
    expect(peage.isPlatformEnabled(PLATFORM_APP_ATTEST)).toBe(false)
  })
})

describe('startup warnings', () => {
  const playIntegrityWithGoogleRoots = {
    ...PLAY_INTEGRITY_CONFIG,
    keyAttestation: { loadRevokedSerialNumbers: async () => new Set<string>() },
  }

  beforeEach(() => {
    vi.spyOn(console, 'warn').mockImplementation(() => undefined)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('warns that App Attest accepts development attestations', () => {
    createPeage({ appAttest: APP_ATTEST_CONFIG, store: createTestStore().store })
    expect(console.warn).toHaveBeenCalledWith(
      expect.stringMatching(/App Attest accepts development attestations/),
    )
  })

  it('warns that Play Integrity accepts apps Play does not recognize', () => {
    const playIntegrity = { ...playIntegrityWithGoogleRoots, allowUnrecognizedApps: true }
    createPeage({ playIntegrity, store: createTestStore().store })
    expect(console.warn).toHaveBeenCalledWith(
      expect.stringMatching(/Play Integrity accepts apps Play does not recognize/),
    )
  })

  it("warns that key attestation trusts the configured roots instead of Google's", () => {
    createPeage({ playIntegrity: PLAY_INTEGRITY_CONFIG, store: createTestStore().store })
    expect(console.warn).toHaveBeenCalledWith(
      expect.stringMatching(/trusts the configured roots instead of Google's/),
    )
  })

  it('does not warn for a production config', () => {
    createPeage({
      appAttest: { appId: IOS_27_DEVICE.appId },
      playIntegrity: playIntegrityWithGoogleRoots,
      store: createTestStore().store,
    })
    expect(console.warn).not.toHaveBeenCalled()
  })
})

describe('createChallenge', () => {
  it('issues 32 random bytes as base64url', async () => {
    const { peage } = createAndroidPeage()
    expect(await peage.createChallenge(PLATFORM_PLAY_INTEGRITY)).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })

  it('refuses a platform that is not configured', async () => {
    const { peage } = createAndroidPeage()
    await expectPeageError(peage.createChallenge(PLATFORM_APP_ATTEST), 'PLATFORM_DISABLED')
  })
})

describe('solveChallenge', () => {
  it('refuses to register for a platform that is not configured', async () => {
    const { peage } = createAndroidPeage()
    const registration = {
      platform: PLATFORM_APP_ATTEST,
      challenge: UNISSUED_CHALLENGE,
      keyId: keyIdFor(newDeviceKey()),
      proof: new Uint8Array(),
    }
    await expectPeageError(peage.solveChallenge(registration), 'PLATFORM_DISABLED')
  })

  it('registers the key and reports it', async () => {
    const { peage, keys, events } = createAndroidPeage()
    const deviceKey = newDeviceKey()
    const challenge = await peage.createChallenge(PLATFORM_PLAY_INTEGRITY)

    const record = await peage.solveChallenge(androidRegistration(challenge, deviceKey))

    expect(record.keyId).toBe(keyIdFor(deviceKey))
    expect(record.appId).toBe(PACKAGE_NAME)
    expect(record.environment).toBe('production')
    expect(keys.get(record.keyId)).toStrictEqual(record)
    expect(events).toStrictEqual([
      { type: 'registration.accepted', keyId: record.keyId, platform: PLATFORM_PLAY_INTEGRITY },
    ])
  })

  it('fails as a server error while the revocation list is unavailable', async () => {
    const keyAttestation = {
      ...PLAY_INTEGRITY_CONFIG.keyAttestation,
      loadRevokedSerialNumbers: () => Promise.reject(new Error('offline')),
    }
    const peage = createPeage({
      playIntegrity: { ...PLAY_INTEGRITY_CONFIG, keyAttestation },
      store: createTestStore().store,
    })
    const challenge = await peage.createChallenge(PLATFORM_PLAY_INTEGRITY)
    await expect(
      peage.solveChallenge(androidRegistration(challenge, newDeviceKey())),
    ).rejects.toSatisfy((error) => !(error instanceof PeageError))
  })

  it('rejects a challenge that was never issued', async () => {
    const { peage } = createAndroidPeage()
    await expectPeageError(
      peage.solveChallenge(androidRegistration(UNISSUED_CHALLENGE, newDeviceKey())),
      'CHALLENGE_UNKNOWN',
    )
  })

  it('rejects a challenge once it has expired', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    const { peage } = createAndroidPeage()
    const challenge = await peage.createChallenge(PLATFORM_PLAY_INTEGRITY)
    vi.advanceTimersByTime(5 * 60 * 1000)
    await expectPeageError(
      peage.solveChallenge(androidRegistration(challenge, newDeviceKey())),
      'CHALLENGE_UNKNOWN',
    )
  })

  it('consumes a challenge even when its attestation fails', async () => {
    const { peage, events } = createAndroidPeage()
    const challenge = await peage.createChallenge(PLATFORM_PLAY_INTEGRITY)
    const forged = { ...androidRegistration(challenge, newDeviceKey()), proof: new Uint8Array() }

    await expectPeageError(peage.solveChallenge(forged), 'ATTESTATION_INVALID')
    await expectPeageError(peage.solveChallenge(forged), 'CHALLENGE_UNKNOWN')
    expect(events.map((event) => event.type)).toStrictEqual([
      'registration.rejected',
      'registration.rejected',
    ])
  })

  it('reports the keyId and platform of a rejected registration', async () => {
    const { peage, events } = createAndroidPeage()
    const registration = androidRegistration(UNISSUED_CHALLENGE, newDeviceKey())

    await expectPeageError(peage.solveChallenge(registration), 'CHALLENGE_UNKNOWN')
    expect(events).toStrictEqual([
      {
        type: 'registration.rejected',
        keyId: registration.keyId,
        platform: PLATFORM_PLAY_INTEGRITY,
        error: expect.any(PeageError),
      },
    ])
  })

  it('rejects a key id that is not canonical base64', async () => {
    const { peage } = createAndroidPeage()
    const challenge = await peage.createChallenge(PLATFORM_PLAY_INTEGRITY)
    const registration = androidRegistration(challenge, newDeviceKey())
    const unpadded = { ...registration, keyId: registration.keyId.replace(/=$/, '') }
    await expectPeageError(peage.solveChallenge(unpadded), 'REQUEST_MALFORMED')
  })

  it('refuses to move a registered key to another platform', async () => {
    const { peage, keys } = createAndroidPeage()
    const deviceKey = newDeviceKey()
    const keyId = keyIdFor(deviceKey)
    keys.set(keyId, {
      keyId,
      platform: PLATFORM_APP_ATTEST,
      appId: 'ABCDE12345.dev.peage',
      environment: 'production',
      publicKey: '',
      attestedAt: 0,
    })

    const challenge = await peage.createChallenge(PLATFORM_PLAY_INTEGRITY)
    await expectPeageError(
      peage.solveChallenge(androidRegistration(challenge, deviceKey)),
      'ATTESTATION_INVALID',
    )
    expect(keys.get(keyId)?.platform).toBe(PLATFORM_APP_ATTEST)
  })

  it.each([
    {
      hook: 'a throwing',
      onEvent: () => {
        throw new Error('hook bug')
      },
    },
    {
      hook: 'a rejecting async',
      onEvent: async () => {
        throw new Error('async hook bug')
      },
    },
  ])("doesn't let $hook event hook change the verdict", async ({ onEvent }) => {
    const peage = createPeage({
      playIntegrity: PLAY_INTEGRITY_CONFIG,
      store: createTestStore().store,
      onEvent,
    })
    const challenge = await peage.createChallenge(PLATFORM_PLAY_INTEGRITY)
    await expect(
      peage.solveChallenge(androidRegistration(challenge, newDeviceKey())),
    ).resolves.toMatchObject({ platform: PLATFORM_PLAY_INTEGRITY })
  })

  it.each([42, 44, 128 * 1024])(
    'rejects a %i-character challenge, which cannot be one Péage issued, before the store sees it',
    async (length) => {
      const takeChallenge = vi.fn(async () => null)
      const store: PeageStore = { ...createTestStore().store, takeChallenge }
      const peage = createPeage({ playIntegrity: PLAY_INTEGRITY_CONFIG, store })
      await expectPeageError(
        peage.solveChallenge(androidRegistration('A'.repeat(length), newDeviceKey())),
        'REQUEST_MALFORMED',
      )
      expect(takeChallenge).not.toHaveBeenCalled()
    },
  )

  it('lets store failures through as plain errors', async () => {
    const failingStore: PeageStore = {
      ...createTestStore().store,
      async takeChallenge() {
        throw new Error('ECONNREFUSED')
      },
    }
    const peage = createPeage({ playIntegrity: PLAY_INTEGRITY_CONFIG, store: failingStore })
    const registration = androidRegistration(UNISSUED_CHALLENGE, newDeviceKey())
    await expect(peage.solveChallenge(registration)).rejects.toSatisfy(
      (error) => !(error instanceof PeageError),
    )
  })
})

describe('App Attest with a real iOS 27 device', () => {
  const registration = {
    platform: PLATFORM_APP_ATTEST,
    challenge: IOS_27_ATTESTATION.challenge,
    keyId: IOS_27_DEVICE.keyId,
    proof: IOS_27_ATTESTATION.proof,
  }

  async function issueChallenge(store: PeageStore, platform: Platform): Promise<void> {
    await store.saveChallenge({
      value: IOS_27_ATTESTATION.challenge,
      platform,
      expiresAt: Date.now() + CHALLENGE_TTL_MS,
    })
  }

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(IOS_27_ATTESTATION.verifiedAt)
  })

  it('registers the device key as a development key of its app, then verifies its signed request', async () => {
    const { peage, store } = createIosPeage()
    await issueChallenge(store, PLATFORM_APP_ATTEST)

    const record = await peage.solveChallenge(registration)
    expect(record.appId).toBe(IOS_27_DEVICE.appId)
    expect(record.environment).toBe('development')

    vi.setSystemTime(IOS_27_ASSERTION.verifiedAt)
    const verified = await peage.verifyAssertion({
      keyId: IOS_27_DEVICE.keyId,
      method: IOS_27_ASSERTION.method,
      path: IOS_27_ASSERTION.path,
      assertion: IOS_27_ASSERTION.assertion,
      readBody: async () => IOS_27_ASSERTION.body,
    })
    expect(verified).toStrictEqual({
      keyId: IOS_27_DEVICE.keyId,
      platform: PLATFORM_APP_ATTEST,
      body: IOS_27_ASSERTION.body,
    })
  })

  it('rejects a tampered attestation as an invalid attestation', async () => {
    const { peage, store } = createIosPeage()
    await issueChallenge(store, PLATFORM_APP_ATTEST)
    const tampered = { ...registration, proof: flipLastByte(registration.proof) }
    await expectPeageError(peage.solveChallenge(tampered), 'ATTESTATION_INVALID')
  })

  it('does not redeem a challenge issued for Play Integrity as an App Attest one', async () => {
    const { store } = createTestStore()
    const peage = createPeage({
      appAttest: APP_ATTEST_CONFIG,
      playIntegrity: PLAY_INTEGRITY_CONFIG,
      store,
    })
    await issueChallenge(store, PLATFORM_PLAY_INTEGRITY)
    await expectPeageError(peage.solveChallenge(registration), 'CHALLENGE_UNKNOWN')
  })
})

describe('verifyAssertion', () => {
  const keyId = keyIdFor(newDeviceKey())

  it('verifies a signed request, returns its body and reports it', async () => {
    const { peage, events } = createAndroidPeage()
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const challenge = await peage.createChallenge(PLATFORM_PLAY_INTEGRITY)
    const record = await peage.solveChallenge(androidRegistration(challenge, publicKey))
    const body = new TextEncoder().encode('{"hello":"world"}')
    const assertion = signPlayIntegrityRequest({
      privateKey,
      method: 'POST',
      path: '/api/echo',
      body,
    })
    const readBody = vi.fn(async () => body)

    const verified = await peage.verifyAssertion({
      keyId: record.keyId,
      method: 'POST',
      path: '/api/echo',
      assertion,
      readBody,
    })

    expect(verified).toStrictEqual({ keyId: record.keyId, platform: PLATFORM_PLAY_INTEGRITY, body })
    expect(readBody).toHaveBeenCalledTimes(1)
    expect(events).toStrictEqual([
      { type: 'registration.accepted', keyId: record.keyId, platform: PLATFORM_PLAY_INTEGRITY },
      { type: 'request.verified', keyId: record.keyId, platform: PLATFORM_PLAY_INTEGRITY },
    ])
  })

  it('rejects a request whose signature was tampered with as an invalid signature', async () => {
    const { peage } = createAndroidPeage()
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const challenge = await peage.createChallenge(PLATFORM_PLAY_INTEGRITY)
    const record = await peage.solveChallenge(androidRegistration(challenge, publicKey))
    const assertion = signPlayIntegrityRequest({
      privateKey,
      method: 'GET',
      path: '/',
      body: new Uint8Array(),
    })

    await expectPeageError(
      peage.verifyAssertion({
        keyId: record.keyId,
        method: 'GET',
        path: '/',
        assertion: flipLastByte(assertion),
        readBody: readEmptyBody,
      }),
      'SIGNATURE_INVALID',
    )
  })

  it('rejects an unknown key without reading the body', async () => {
    const { peage, events } = createAndroidPeage()
    const readBody = vi.fn(readEmptyBody)
    await expectPeageError(
      peage.verifyAssertion({
        keyId,
        method: 'GET',
        path: '/',
        assertion: new Uint8Array(),
        readBody,
      }),
      'KEY_UNKNOWN',
    )
    expect(readBody).not.toHaveBeenCalled()
    expect(events.map((event) => event.type)).toStrictEqual(['request.rejected'])
  })

  it.each(['get', 'GET\n'])('rejects the method %j before looking up the key', async (method) => {
    const loadAttestedKey = vi.fn(async () => null)
    const store: PeageStore = { ...createTestStore().store, loadAttestedKey }
    const peage = createPeage({ playIntegrity: PLAY_INTEGRITY_CONFIG, store })
    await expectPeageError(
      peage.verifyAssertion({
        keyId,
        method,
        path: '/',
        assertion: new Uint8Array(),
        readBody: readEmptyBody,
      }),
      'REQUEST_MALFORMED',
    )
    expect(loadAttestedKey).not.toHaveBeenCalled()
  })

  it('treats a stored key that cannot be imported as a server failure', async () => {
    const { peage, keys } = createAndroidPeage()
    keys.set(keyId, {
      keyId,
      platform: PLATFORM_PLAY_INTEGRITY,
      appId: PACKAGE_NAME,
      environment: 'production',
      publicKey: 'AAAA',
      attestedAt: 0,
    })
    await expect(
      peage.verifyAssertion({
        keyId,
        method: 'GET',
        path: '/',
        assertion: new Uint8Array(),
        readBody: readEmptyBody,
      }),
    ).rejects.toSatisfy((error) => !(error instanceof PeageError))
  })

  it.each([
    {
      platform: PLATFORM_APP_ATTEST,
      appId: 'ABCDE12345.dev.peage',
      createPeageWithout: createAndroidPeage,
    },
    { platform: PLATFORM_PLAY_INTEGRITY, appId: PACKAGE_NAME, createPeageWithout: createIosPeage },
  ])(
    'rejects assertions from a $platform key once $platform is no longer configured, without reading the body',
    async ({ platform, appId, createPeageWithout }) => {
      const { peage, keys } = createPeageWithout()
      const readBody = vi.fn(readEmptyBody)
      const publicKey = toBase64(newDeviceKey().export({ format: 'der', type: 'spki' }))
      keys.set(keyId, {
        keyId,
        platform,
        appId,
        environment: 'production',
        publicKey,
        attestedAt: 0,
      })
      await expectPeageError(
        peage.verifyAssertion({
          keyId,
          method: 'GET',
          path: '/',
          assertion: new Uint8Array(),
          readBody,
        }),
        'PLATFORM_DISABLED',
      )
      expect(readBody).not.toHaveBeenCalled()
    },
  )

  it.each([
    { attestationCertificateSerialNumbers: ['1', 'abc'] },
    { attestationCertificateSerialNumbers: ['abc', '1'] },
    { attestationCertificateSerialNumbers: ['1', '2', 'abc'] },
  ])(
    'answers a revoked key as unknown when its stored serial numbers are $attestationCertificateSerialNumbers, without reading the body',
    async ({ attestationCertificateSerialNumbers }) => {
      const keyAttestation = {
        ...PLAY_INTEGRITY_CONFIG.keyAttestation,
        loadRevokedSerialNumbers: async () => new Set(['abc']),
      }
      const { store, keys } = createTestStore()
      const peage = createPeage({
        playIntegrity: { ...PLAY_INTEGRITY_CONFIG, keyAttestation },
        store,
      })
      const readBody = vi.fn(readEmptyBody)
      keys.set(keyId, {
        keyId,
        platform: PLATFORM_PLAY_INTEGRITY,
        appId: PACKAGE_NAME,
        environment: 'production',
        publicKey: toBase64(newDeviceKey().export({ format: 'der', type: 'spki' })),
        attestedAt: 0,
        attestationCertificateSerialNumbers,
      })
      await expectPeageError(
        peage.verifyAssertion({
          keyId,
          method: 'GET',
          path: '/',
          assertion: new Uint8Array(),
          readBody,
        }),
        'KEY_UNKNOWN',
      )
      expect(readBody).not.toHaveBeenCalled()
    },
  )

  it.each([
    {
      platformName: 'an App Attest',
      platform: PLATFORM_APP_ATTEST,
      appId: 'ABCDE12345.dev.other',
      createPeageWith: createIosPeage,
    },
    {
      platformName: 'a Play Integrity',
      platform: PLATFORM_PLAY_INTEGRITY,
      appId: 'dev.peage.other',
      createPeageWith: createAndroidPeage,
    },
  ])(
    'answers $platformName key registered by another app as unknown, without reading the body',
    async ({ platform, appId, createPeageWith }) => {
      const { peage, keys } = createPeageWith()
      const readBody = vi.fn(readEmptyBody)
      const publicKey = toBase64(newDeviceKey().export({ format: 'der', type: 'spki' }))
      keys.set(keyId, {
        keyId,
        platform,
        appId,
        environment: 'production',
        publicKey,
        attestedAt: 0,
      })
      await expectPeageError(
        peage.verifyAssertion({
          keyId,
          method: 'GET',
          path: '/',
          assertion: new Uint8Array(),
          readBody,
        }),
        'KEY_UNKNOWN',
      )
      expect(readBody).not.toHaveBeenCalled()
    },
  )
})
