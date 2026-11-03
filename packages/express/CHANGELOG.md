# @peage/express

## 0.4.0

### Minor Changes

- 4cce460: Registered keys now expire after 30 days. When a device signs a request with an expired key, the server answers `401 unknown_key`, and the client registers a new key and retries, so the device goes through the attestation checks again. Change the duration with the new `maxKeyAgeSeconds` option, or set it to `Infinity` to keep keys forever.

  If you wrote your own store: key records now carry an `expiresAt`, after which you can delete them.

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

- b7d6256: Add `peage.router`, an Express router serving `challenge` at `POST CHALLENGE_PATH` and `solve` at `POST SOLVE_PATH`, so `app.use('/v1', peage.router)` mounts both under a prefix.
- b7d6256: Add a `debugToken` option for development: a protected request carrying it in `X-Peage-Debug-Token` is accepted without a registered key or signature. `createPeage` refuses it unless every configured platform accepts development builds, or when it is shorter than 32 characters. `VerifiedRequest` and the `request.verified` event now carry `debug`: check `debug` is false before reading `keyId` and `platform`.

### Patch Changes

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
