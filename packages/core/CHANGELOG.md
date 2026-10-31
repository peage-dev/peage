# @peage/core

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
