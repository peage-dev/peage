import type { AttestedKeyRecord, IssuedChallenge } from '@peage/core'

import type { RedisStore, RedisStoreOptions } from './types.ts'

import { assertAttestedKeyRecord, assertIssuedChallenge } from './asserters.ts'

export type { RedisCommands, RedisStore, RedisStoreOptions } from './types.ts'

function parseStoredJson(json: string, name: string): unknown {
  try {
    return JSON.parse(json)
  } catch (error) {
    throw new Error(`Péage found a malformed ${name} in Redis`, { cause: error })
  }
}

function parseChallenge(json: string): IssuedChallenge {
  const value = parseStoredJson(json, 'challenge')
  assertIssuedChallenge(value)
  return value
}

function parseAttestedKeyRecord(json: string): AttestedKeyRecord {
  const value = parseStoredJson(json, 'key record')
  assertAttestedKeyRecord(value)
  return value
}

/** Challenges expire with Redis's own TTL; key records are kept until deleted. */
export function createRedisStore(options: RedisStoreOptions): RedisStore {
  const { redis } = options
  const keyPrefix = options.keyPrefix ?? 'peage:'

  function challengeKey(challenge: Pick<IssuedChallenge, 'value' | 'platform'>): string {
    return `${keyPrefix}challenge:${challenge.platform}:${challenge.value}`
  }

  function attestedKeyKey(keyId: string): string {
    return `${keyPrefix}key:${keyId}`
  }

  return {
    async saveChallenge(challenge) {
      await redis.set(challengeKey(challenge), JSON.stringify(challenge), challenge.expiresAt)
    },
    async takeChallenge(challenge) {
      const json = await redis.getDel(challengeKey(challenge))
      return json === null ? null : parseChallenge(json)
    },
    async saveAttestedKey(record) {
      await redis.set(attestedKeyKey(record.keyId), JSON.stringify(record))
    },
    async loadAttestedKey({ keyId }) {
      const json = await redis.get(attestedKeyKey(keyId))
      return json === null ? null : parseAttestedKeyRecord(json)
    },
    async deleteAttestedKey({ keyId }) {
      await redis.del(attestedKeyKey(keyId))
    },
  }
}
