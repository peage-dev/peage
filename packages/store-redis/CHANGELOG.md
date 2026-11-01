# @peage/store-redis

## 0.3.0

### Minor Changes

- b7d6256: Add `fromIoredis(client)` and `fromNodeRedis(client)`, which adapt an ioredis or node-redis (`redis`) client to `RedisCommands`. `ioredis` 5+ and `redis` 4+ are optional peer dependencies.

### Patch Changes

- b7d6256: A stored challenge or key record that doesn't parse or has the wrong shape is now treated as absent instead of throwing.
- Updated dependencies [b7d6256]
  - @peage/core@0.3.0
  - @peage/protocol@0.3.0

## 0.2.0

### Patch Changes

- Updated dependencies [032bac9]
  - @peage/core@0.2.0
  - @peage/protocol@0.2.0

## 0.1.0

### Minor Changes

- Initial release.

### Patch Changes

- Updated dependencies
  - @peage/protocol@0.1.0
  - @peage/core@0.1.0
