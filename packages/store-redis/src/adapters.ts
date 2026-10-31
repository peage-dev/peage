import type { IoredisClient, NodeRedisClient, RedisCommands } from './types.ts'

/** Adapts an ioredis client to `RedisCommands`. */
export function fromIoredis(client: IoredisClient): RedisCommands {
  return {
    get: (key) => client.get(key),
    getDel: (key) => client.getdel(key),
    set: (key, value, expiresAt) =>
      expiresAt === undefined ? client.set(key, value) : client.set(key, value, 'PXAT', expiresAt),
    del: (key) => client.del(key),
  }
}

/** Adapts a node-redis (`redis`) client to `RedisCommands`. */
export function fromNodeRedis(client: NodeRedisClient): RedisCommands {
  return {
    get: (key) => client.get(key),
    getDel: (key) => client.getDel(key),
    set: (key, value, expiresAt) =>
      expiresAt === undefined
        ? client.set(key, value)
        : client.set(key, value, { PXAT: expiresAt }),
    del: (key) => client.del(key),
  }
}
