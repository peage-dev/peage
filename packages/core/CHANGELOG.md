# @peage/core

## 0.3.0

### Minor Changes

- b7d6256: Add a `debugToken` option for development: a protected request carrying it in `X-Peage-Debug-Token` is accepted without a registered key or signature. `createPeage` refuses it unless every configured platform accepts development builds, or when it is shorter than 32 characters. `VerifiedRequest` and the `request.verified` event now carry `debug`: check `debug` is false before reading `keyId` and `platform`.

### Patch Changes

- b7d6256: A signed request whose stored key record holds a public key that can't be imported is now rejected as an unknown key (`401`, `unknown_key`), so the client registers again, instead of failing as a server error.
- Updated dependencies [b7d6256]
  - @peage/protocol@0.3.0

## 0.2.0

### Minor Changes

- 032bac9: On `registration.rejected` and `request.rejected` events, `keyId` is now optional and present only when it is well-formed. On `registration.rejected`, `platform` is now optional and present only when it is one Péage supports.

### Patch Changes

- 032bac9: Measure a signed request's time window from when the server starts handling it, so a request whose body takes long to upload is no longer rejected as an invalid signature.
- Updated dependencies
  - @peage/protocol@0.2.0

## 0.1.0

### Minor Changes

- Initial release.

### Patch Changes

- Updated dependencies
  - @peage/protocol@0.1.0
