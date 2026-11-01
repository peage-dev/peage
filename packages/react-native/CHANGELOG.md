# @peage/react-native

## 0.3.0

### Minor Changes

- b7d6256: Add a `debugToken` option for development: on a device that can't attest, e.g. a simulator or Expo Go, `fetch` sends it in `X-Peage-Debug-Token` instead of registering and signing. The server must be configured with the same token. Android emulators with the Play Store count as able to attest.
- d1fdb83: Supports React Native 0.76 and later; it required 0.88 before.
- b7d6256: Generate one native assertion at a time per native module, so concurrent `fetch` calls no longer fail with App Attest's `DCError` 0; requests are still sent in parallel.
- b7d6256: `createPeageClient` no longer throws when the native module isn't linked, e.g. in Expo Go: `isSupported()` resolves false, and `register()` and `fetch()` reject with `UNSUPPORTED`, saying the native module isn't linked.

### Patch Changes

- Updated dependencies [b7d6256]
  - @peage/protocol@0.3.0

## 0.2.0

### Minor Changes

- ab507bb: Add `challengePath` and `solvePath` options to `createPeageClient`, resolved like `fetch`'s input: a path appended to `baseUrl`'s path, or a URL on `baseUrl`'s origin.

### Patch Changes

- Updated dependencies
  - @peage/protocol@0.2.0

## 0.1.0

### Minor Changes

- Initial release.

### Patch Changes

- Updated dependencies
  - @peage/protocol@0.1.0
