import type { AttestedKeyRecord } from '@peage/core'

import { PLATFORM_APP_ATTEST, PLATFORM_PLAY_INTEGRITY } from '@peage/protocol'
import { describe, expect, it } from 'vitest'

import { createMemoryStore } from '../index.ts'

const challenge = {
  value: 'challenge',
  platform: PLATFORM_APP_ATTEST,
  expiresAt: Date.now() + 60_000,
}

const record: AttestedKeyRecord = {
  keyId: 'key',
  platform: PLATFORM_APP_ATTEST,
  appId: 'ABCDE12345.dev.peage',
  environment: 'production',
  publicKey: 'spki',
  attestedAt: 1,
}

describe('createMemoryStore', () => {
  it('hands out a challenge only once', async () => {
    const store = createMemoryStore()
    await store.saveChallenge(challenge)
    expect(await store.takeChallenge(challenge)).toStrictEqual(challenge)
    expect(await store.takeChallenge(challenge)).toBeNull()
  })

  it('keeps challenges of different platforms apart', async () => {
    const store = createMemoryStore()
    await store.saveChallenge(challenge)
    expect(
      await store.takeChallenge({ ...challenge, platform: PLATFORM_PLAY_INTEGRITY }),
    ).toBeNull()
  })

  it('drops expired challenges when new ones are saved', async () => {
    const store = createMemoryStore()
    const expired = { ...challenge, value: 'expired', expiresAt: Date.now() - 1 }
    await store.saveChallenge(expired)
    await store.saveChallenge(challenge)
    expect(await store.takeChallenge(expired)).toBeNull()
    expect(await store.takeChallenge(challenge)).toStrictEqual(challenge)
  })

  it('stores attested keys by keyId, replacing earlier records', async () => {
    const store = createMemoryStore()
    await store.saveAttestedKey(record)
    await store.saveAttestedKey({ ...record, attestedAt: 2 })
    expect(await store.loadAttestedKey({ keyId: 'key' })).toStrictEqual({
      ...record,
      attestedAt: 2,
    })
    expect(await store.loadAttestedKey({ keyId: 'other' })).toBeNull()
  })

  it('deletes an attested key by keyId', async () => {
    const store = createMemoryStore()
    await store.saveAttestedKey(record)
    await store.saveAttestedKey({ ...record, keyId: 'other' })
    await store.deleteAttestedKey({ keyId: 'key' })
    expect(await store.loadAttestedKey({ keyId: 'key' })).toBeNull()
    expect(await store.loadAttestedKey({ keyId: 'other' })).toStrictEqual({
      ...record,
      keyId: 'other',
    })
  })
})
