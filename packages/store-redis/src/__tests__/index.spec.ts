import type { AttestedKeyRecord, IssuedChallenge } from '@peage/core'

import { PLATFORM_APP_ATTEST, PLATFORM_PLAY_INTEGRITY } from '@peage/protocol'
import { Redis } from 'ioredis'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import { createRedisStore, type RedisCommands } from '../index.ts'
import { type RedisContainer, startRedisContainer } from './redisContainer.ts'

let container: RedisContainer
let client: Redis
let redis: RedisCommands

function ioredisCommands(ioredis: Redis): RedisCommands {
  return {
    get: (key) => ioredis.get(key),
    getDel: (key) => ioredis.getdel(key),
    set: (key, value, expiresAt) =>
      expiresAt === undefined
        ? ioredis.set(key, value)
        : ioredis.set(key, value, 'PXAT', expiresAt),
    del: (key) => ioredis.del(key),
  }
}

beforeAll(async () => {
  container = await startRedisContainer()
  client = new Redis(container.url)
  redis = ioredisCommands(client)
}, 120_000)

afterAll(async () => {
  client.disconnect()
  await container.stop()
})

beforeEach(async () => {
  await client.flushall()
})

function newChallenge(): IssuedChallenge {
  return { value: 'challenge', platform: PLATFORM_APP_ATTEST, expiresAt: Date.now() + 60_000 }
}

const record: AttestedKeyRecord = {
  keyId: 'k3y/Id+==',
  platform: PLATFORM_PLAY_INTEGRITY,
  appId: 'dev.peage.rnexample',
  environment: 'production',
  publicKey: 'spki',
  attestedAt: 1,
  attestationCertificateSerialNumbers: ['1', '-7fff'],
}

describe('createRedisStore', () => {
  it('hands out a challenge only once', async () => {
    const store = createRedisStore({ redis })
    const challenge = newChallenge()
    await store.saveChallenge(challenge)
    expect(await store.takeChallenge(challenge)).toStrictEqual(challenge)
    expect(await store.takeChallenge(challenge)).toBeNull()
  })

  it('hands out a challenge to exactly one of many concurrent takers', async () => {
    const store = createRedisStore({ redis })
    const challenge = newChallenge()
    await store.saveChallenge(challenge)
    const taken = await Promise.all(
      Array.from({ length: 20 }, () => store.takeChallenge(challenge)),
    )
    expect(taken.filter((result) => result !== null)).toStrictEqual([challenge])
  })

  it('keeps challenges of different platforms apart', async () => {
    const store = createRedisStore({ redis })
    const challenge = newChallenge()
    await store.saveChallenge(challenge)
    expect(
      await store.takeChallenge({ ...challenge, platform: PLATFORM_PLAY_INTEGRITY }),
    ).toBeNull()
  })

  it('lets Redis expire a challenge at its expiresAt', async () => {
    const store = createRedisStore({ redis })
    const challenge = { ...newChallenge(), expiresAt: Date.now() + 50 }
    await store.saveChallenge(challenge)
    await new Promise((resolve) => setTimeout(resolve, 100))
    expect(await store.takeChallenge(challenge)).toBeNull()
  })

  it('stores attested keys by keyId, replacing earlier records', async () => {
    const store = createRedisStore({ redis })
    await store.saveAttestedKey(record)
    await store.saveAttestedKey({ ...record, attestedAt: 2 })
    expect(await store.loadAttestedKey({ keyId: record.keyId })).toStrictEqual({
      ...record,
      attestedAt: 2,
    })
    expect(await store.loadAttestedKey({ keyId: 'other' })).toBeNull()
  })

  it('deletes an attested key by keyId', async () => {
    const store = createRedisStore({ redis })
    const otherRecord = { ...record, keyId: 'other' }
    await store.saveAttestedKey(record)
    await store.saveAttestedKey(otherRecord)
    await store.deleteAttestedKey({ keyId: record.keyId })
    expect(await store.loadAttestedKey({ keyId: record.keyId })).toBeNull()
    expect(await store.loadAttestedKey({ keyId: 'other' })).toStrictEqual(otherRecord)
  })

  it('never expires key records', async () => {
    const store = createRedisStore({ redis })
    await store.saveAttestedKey(record)
    expect(await client.pttl(`peage:key:${record.keyId}`)).toBe(-1)
  })

  it('returns an App Attest record, which has no serial numbers, as saved', async () => {
    const store = createRedisStore({ redis })
    const appAttestRecord: AttestedKeyRecord = {
      keyId: 'app/Attest+Key=',
      platform: PLATFORM_APP_ATTEST,
      appId: 'ABCDE12345.dev.peage',
      environment: 'development',
      publicKey: 'spki',
      attestedAt: 3,
    }
    await store.saveAttestedKey(appAttestRecord)
    expect(await store.loadAttestedKey({ keyId: appAttestRecord.keyId })).toStrictEqual(
      appAttestRecord,
    )
  })

  it('keeps stores with different key prefixes apart', async () => {
    const first = createRedisStore({ redis, keyPrefix: 'first:' })
    const second = createRedisStore({ redis, keyPrefix: 'second:' })
    const challenge = newChallenge()
    await first.saveChallenge(challenge)
    await first.saveAttestedKey(record)
    expect(await second.takeChallenge(challenge)).toBeNull()
    expect(await second.loadAttestedKey({ keyId: record.keyId })).toBeNull()
  })

  it.each([
    ['a challenge that is not an object', null],
    ['a challenge with a non-string value', { ...newChallenge(), value: 42 }],
    ['a challenge with an unknown platform', { ...newChallenge(), platform: 'web' }],
    ['a challenge with a non-number expiresAt', { ...newChallenge(), expiresAt: 'soon' }],
  ])('refuses %s', async (_case, stored) => {
    const store = createRedisStore({ redis })
    const challenge = newChallenge()
    await client.set(
      `peage:challenge:${challenge.platform}:${challenge.value}`,
      JSON.stringify(stored),
    )
    await expect(store.takeChallenge(challenge)).rejects.toThrow(/malformed challenge/)
  })

  it('refuses a key record that is not JSON', async () => {
    const store = createRedisStore({ redis })
    await client.set(`peage:key:${record.keyId}`, '{not json')
    await expect(store.loadAttestedKey({ keyId: record.keyId })).rejects.toThrow(
      /malformed key record/,
    )
  })

  it.each([
    ['a key record that is not an object', null],
    ['a key record with a non-string keyId', { ...record, keyId: 42 }],
    ['a key record with an unknown platform', { ...record, platform: 'web' }],
    ['a key record with a non-string appId', { ...record, appId: 42 }],
    ['a key record with an unknown environment', { ...record, environment: 'staging' }],
    ['a key record with a non-string publicKey', { ...record, publicKey: 42 }],
    ['a key record with a non-number attestedAt', { ...record, attestedAt: '1' }],
    [
      'a key record whose serial numbers are not a list',
      { ...record, attestationCertificateSerialNumbers: '1' },
    ],
    [
      'a key record whose serial numbers include a non-string',
      { ...record, attestationCertificateSerialNumbers: ['1', 2] },
    ],
  ])('refuses %s', async (_case, stored) => {
    const store = createRedisStore({ redis })
    await client.set(`peage:key:${record.keyId}`, JSON.stringify(stored))
    await expect(store.loadAttestedKey({ keyId: record.keyId })).rejects.toThrow(
      /malformed key record/,
    )
  })
})
