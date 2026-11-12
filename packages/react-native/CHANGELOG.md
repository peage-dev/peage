# @peage/react-native

## 0.4.2

### Patch Changes

- 98a06b6: On iOS, the client no longer gets stuck after the app is deleted and reinstalled. The keyId was kept in the Keychain, which outlives the app, while its App Attest key doesn't, so every request failed with `NATIVE` (`cause.code` `E_INVALID_INPUT`) before reaching the server. The keyId now lives in UserDefaults, which is deleted with the app; one stored by an earlier version moves there on first use, so updating keeps the registered key. A stored keyId that iOS still rejects this way is replaced by registering once. Apps that catch `E_INVALID_INPUT`, call `clearKey()` and retry can drop that workaround on this version; it still works, but is no longer needed. The pod now ships a privacy manifest for its UserDefaults use (reason `CA92.1`).
- Updated dependencies
  - @peage/protocol@0.4.2

## 0.4.1

### Patch Changes

- Updated dependencies
  - @peage/protocol@0.4.1

## 0.4.0

### Patch Changes

- Updated dependencies
  - @peage/protocol@0.4.0

## 0.3.1

### Patch Changes

- 0122df8: With `debugToken` set, `fetch` now always sends it instead of registering and signing, including on devices that can attest.
- Updated dependencies
  - @peage/protocol@0.3.1

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
