---
'@peage/store-redis': minor
---

Add `fromIoredis(client)` and `fromNodeRedis(client)`, which adapt an ioredis or node-redis (`redis`) client to `RedisCommands`. `ioredis` 5+ and `redis` 4+ are optional peer dependencies.
