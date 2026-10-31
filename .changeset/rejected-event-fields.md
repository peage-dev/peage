---
'@peage/core': minor
---

On `registration.rejected` and `request.rejected` events, `keyId` is now optional and present only when it is well-formed. On `registration.rejected`, `platform` is now optional and present only when it is one Péage supports.
