import type { AttestedKeyRecord, IssuedChallenge } from '@peage/core'

import { PLATFORM_APP_ATTEST, PLATFORM_PLAY_INTEGRITY, toBase64 } from '@peage/protocol'
import { Redis } from 'ioredis'
import { generateKeyPairSync } from 'node:crypto'
import { createClient } from 'redis'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import { createRedisStore, fromIoredis, fromNodeRedis, type RedisCommands } from '../index.ts'
import { type RedisContainer, startRedisContainer } from './redisContainer.ts'

type RedisConnection = {
  redis: RedisCommands
  flushAll(): Promise<unknown>
  millisecondsToLive(key: string): Promise<number>
  close(): Promise<void>
}

async function connectIoredis(url: string): Promise<RedisConnection> {
  const client = new Redis(url)
  return {
    redis: fromIoredis(client),
    flushAll: () => client.flushall(),
    millisecondsToLive: (key) => client.pttl(key),
    close: async () => {
      await client.quit()
    },
  }
}

async function connectNodeRedis(url: string): Promise<RedisConnection> {
  const client = createClient({ url })
  await client.connect()
  return {
    redis: fromNodeRedis(client),
    flushAll: () => client.flushAll(),
    millisecondsToLive: (key) => client.pTTL(key),
    close: () => client.close(),
  }
}

let container: RedisContainer

beforeAll(async () => {
  container = await startRedisContainer()
}, 120_000)

afterAll(async () => {
  await container.stop()
})

function newChallenge(): IssuedChallenge {
  return { value: 'challenge', platform: PLATFORM_APP_ATTEST, expiresAt: Date.now() + 60_000 }
}

function newPublicKey(): string {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  return toBase64(publicKey.export({ format: 'der', type: 'spki' }))
}

const record: AttestedKeyRecord = {
  keyId: 'k3y/Id+==',
  platform: PLATFORM_PLAY_INTEGRITY,
  appId: 'dev.peage.rnexample',
  environment: 'production',
  publicKey: newPublicKey(),
  attestedAt: 1,
  attestationCertificateSerialNumbers: ['1', '-7fff', '0', 'f0e1d2c3b4a5968778695a4b3c2d1e0f'],
}

const appAttestRecord: AttestedKeyRecord = {
  keyId: 'app/Attest+Key=',
  platform: PLATFORM_APP_ATTEST,
  appId: 'ABCDE12345.dev.peage',
  environment: 'development',
  publicKey: newPublicKey(),
  attestedAt: 3,
}

describe.each([
  ['ioredis', connectIoredis],
  ['node-redis', connectNodeRedis],
])('createRedisStore with %s', (_client, connect) => {
  let connection: RedisConnection
  let redis: RedisCommands

  beforeAll(async () => {
    connection = await connect(container.url)
    redis = connection.redis
  })

  afterAll(async () => {
    await connection.close()
  })

  beforeEach(async () => {
    await connection.flushAll()
  })

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

  it('never expires a key record without expiresAt', async () => {
    const store = createRedisStore({ redis })
    await store.saveAttestedKey(record)
    expect(await connection.millisecondsToLive(`peage:key:${record.keyId}`)).toBe(-1)
  })

  it('returns a key record with expiresAt as saved, and lets Redis expire it then', async () => {
    const store = createRedisStore({ redis })
    const timeToLive = 3_600_000
    const expiringRecord = { ...record, expiresAt: Date.now() + timeToLive }
    await store.saveAttestedKey(expiringRecord)
    expect(await store.loadAttestedKey({ keyId: record.keyId })).toStrictEqual(expiringRecord)
    const remaining = await connection.millisecondsToLive(`peage:key:${record.keyId}`)
    expect(remaining).toBeGreaterThan(timeToLive - 60_000)
    expect(remaining).toBeLessThanOrEqual(timeToLive + 60_000)
  })

  it('does not keep a key record whose expiresAt has passed', async () => {
    const store = createRedisStore({ redis })
    await store.saveAttestedKey({ ...record, expiresAt: Date.now() - 1 })
    expect(await store.loadAttestedKey({ keyId: record.keyId })).toBeNull()
  })

  it('stores a Play Integrity record as a versioned array without its keyId', async () => {
    const store = createRedisStore({ redis })
    await store.saveAttestedKey(record)
    expect(JSON.parse((await redis.get(`peage:key:${record.keyId}`)) ?? '')).toStrictEqual([
      1,
      1,
      'dev.peage.rnexample',
      0,
      expect.stringMatching(/^[A-Za-z0-9+/]{44}$/),
      1,
      null,
      ['AQ', '-f/8', 'AA', '8OHSw7Sllod4aVpLPC0eDw'],
    ])
  })

  it('stores an App Attest record as a versioned array without trailing absent fields', async () => {
    const store = createRedisStore({ redis })
    await store.saveAttestedKey(appAttestRecord)
    expect(JSON.parse((await redis.get(`peage:key:${appAttestRecord.keyId}`)) ?? '')).toStrictEqual(
      [1, 0, 'ABCDE12345.dev.peage', 1, expect.stringMatching(/^[A-Za-z0-9+/]{44}$/), 3],
    )
  })

  it('returns an App Attest record, which has no serial numbers, as saved', async () => {
    const store = createRedisStore({ redis })
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
  ])('treats %s as absent', async (_case, stored) => {
    const store = createRedisStore({ redis })
    const challenge = newChallenge()
    await redis.set(
      `peage:challenge:${challenge.platform}:${challenge.value}`,
      JSON.stringify(stored),
    )
    expect(await store.takeChallenge(challenge)).toBeNull()
  })

  it('treats a challenge that is not JSON as absent', async () => {
    const store = createRedisStore({ redis })
    const challenge = newChallenge()
    await redis.set(`peage:challenge:${challenge.platform}:${challenge.value}`, '{not json')
    expect(await store.takeChallenge(challenge)).toBeNull()
  })

  it('treats a key record that is not JSON as absent', async () => {
    const store = createRedisStore({ redis })
    await redis.set(`peage:key:${record.keyId}`, '{not json')
    expect(await store.loadAttestedKey({ keyId: record.keyId })).toBeNull()
  })

  it('treats a key record in the JSON object format of 0.3 as absent', async () => {
    const store = createRedisStore({ redis })
    await redis.set(`peage:key:${record.keyId}`, JSON.stringify(record))
    expect(await store.loadAttestedKey({ keyId: record.keyId })).toBeNull()
  })

  it.each([
    ['another format version', 0, 2],
    ['an unknown platform', 1, 2],
    ['a non-string appId', 2, 42],
    ['an unknown environment', 3, 2],
    ['a public key that is not a P-256 point', 4, 'AAAA'],
    ['a non-number attestedAt', 5, '1'],
    ['a non-number expiresAt', 6, 'soon'],
    ['serial numbers that are not a list', 7, 'AQ'],
    ['serial numbers that include a non-string', 7, ['AQ', 2]],
    ['a serial number that is not base64', 7, ['%%']],
  ])('treats a key record with %s as absent', async (_case, index, value) => {
    const store = createRedisStore({ redis })
    const key = `peage:key:${record.keyId}`
    await store.saveAttestedKey(record)
    const stored: unknown[] = JSON.parse((await redis.get(key)) ?? '')
    stored[index] = value
    await redis.set(key, JSON.stringify(stored))
    expect(await store.loadAttestedKey({ keyId: record.keyId })).toBeNull()
  })

  it('replaces a malformed key record when the key is saved again', async () => {
    const store = createRedisStore({ redis })
    await redis.set(`peage:key:${record.keyId}`, '{not json')
    await store.saveAttestedKey(record)
    expect(await store.loadAttestedKey({ keyId: record.keyId })).toStrictEqual(record)
  })
})
