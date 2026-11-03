import type { IssuedChallenge } from '@peage/core'

import type { RedisStore, RedisStoreOptions } from './types.ts'

import { isIssuedChallenge } from './guards.ts'
import { decodeAttestedKeyRecord, encodeAttestedKeyRecord } from './keyRecords.ts'

export { fromIoredis, fromNodeRedis } from './adapters.ts'
export type {
  IoredisClient,
  NodeRedisClient,
  RedisCommands,
  RedisStore,
  RedisStoreOptions,
} from './types.ts'

function parseStoredJson(json: string): unknown {
  try {
    return JSON.parse(json)
  } catch {
    return undefined
  }
}

function parseChallenge(json: string): IssuedChallenge | null {
  const value = parseStoredJson(json)
  return isIssuedChallenge(value) ? value : null
}

/**
 * Challenges, and key records with an `expiresAt`, expire with Redis's own TTL;
 * other key records are kept until deleted. A stored challenge or key record
 * that doesn't parse is treated as absent.
 */
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
      await redis.set(
        attestedKeyKey(record.keyId),
        JSON.stringify(encodeAttestedKeyRecord(record)),
        record.expiresAt,
      )
    },
    async loadAttestedKey({ keyId }) {
      const stored = await redis.get(attestedKeyKey(keyId))
      return stored === null ? null : decodeAttestedKeyRecord(keyId, parseStoredJson(stored))
    },
    async deleteAttestedKey({ keyId }) {
      await redis.del(attestedKeyKey(keyId))
    },
  }
}
