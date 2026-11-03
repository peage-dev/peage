import type { PeageStore } from '@peage/core'

/** The Redis commands the store uses, adapted from any client. Needs Redis 6.2 or later. */
export type RedisCommands = {
  /** `GET key` */
  get(key: string): Promise<string | null>
  /** `GETDEL key` */
  getDel(key: string): Promise<string | null>
  /** `SET key value`, or `SET key value PXAT expiresAt` when `expiresAt` (Unix milliseconds) is given. */
  set(key: string, value: string, expiresAt?: number): Promise<unknown>
  /** `DEL key` */
  del(key: string): Promise<unknown>
}

/** A `PeageStore` that can also delete key records. */
export type RedisStore = PeageStore & {
  /** Deletes the record for `keyId`, if any. */
  deleteAttestedKey(key: { keyId: string }): Promise<void>
}

/** Options for `createRedisStore`. */
export type RedisStoreOptions = {
  /** The Redis client, adapted to `RedisCommands`, e.g. with `fromIoredis` or `fromNodeRedis`. */
  redis: RedisCommands
  /** Prepended to every Redis key. Defaults to `peage:`. */
  keyPrefix?: string
}

/** An ioredis 5+ `Redis` or `Cluster` instance. */
export type IoredisClient = {
  get(key: string): Promise<string | null>
  getdel(key: string): Promise<string | null>
  set(key: string, value: string): Promise<unknown>
  set(key: string, value: string, expiryToken: 'PXAT', expiresAt: number): Promise<unknown>
  del(key: string): Promise<unknown>
}

/** A node-redis (`redis`) 4+ client or cluster. */
export type NodeRedisClient = {
  get(key: string): Promise<string | null>
  getDel(key: string): Promise<string | null>
  set(key: string, value: string, options?: { PXAT: number }): Promise<unknown>
  del(key: string): Promise<unknown>
}

/** A key record as store-redis saves it, without its keyId. */
export type EncodedKeyRecord = [
  version: number,
  platform: number,
  appId: string,
  environment: number,
  publicKey: string,
  attestedAt: number,
  expiresAt?: number | null,
  serialNumbers?: string[] | null,
]
