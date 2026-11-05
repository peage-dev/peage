# @peage/store-redis

## 0.4.1

### Patch Changes

- Updated dependencies [03a2e38]
  - @peage/core@0.4.1
  - @peage/protocol@0.4.1

## 0.4.0

### Minor Changes

- 4cce460: Key records take about half as much memory in Redis, and are deleted when they expire. Records saved by 0.3 can't be read anymore, so those devices register again; the old records stay in Redis until you delete them.

### Patch Changes

- Updated dependencies [4cce460]
  - @peage/core@0.4.0
  - @peage/protocol@0.4.0

## 0.3.1

### Patch Changes

- Updated dependencies
  - @peage/core@0.3.1
  - @peage/protocol@0.3.1

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
