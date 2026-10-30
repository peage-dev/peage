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
  /** The Redis client, adapted to `RedisCommands`. */
  redis: RedisCommands
  /** Prepended to every Redis key. Defaults to `peage:`. */
  keyPrefix?: string
}
