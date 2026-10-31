---
'@peage/core': minor
'@peage/express': minor
---

Add a `debugToken` option for development: a protected request carrying it in `X-Peage-Debug-Token` is accepted without a registered key or signature. `createPeage` refuses it unless every configured platform accepts development builds, or when it is shorter than 32 characters. `VerifiedRequest` and the `request.verified` event now carry `debug`: check `debug` is false before reading `keyId` and `platform`.
