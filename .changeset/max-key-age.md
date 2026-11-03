---
'@peage/core': minor
'@peage/express': minor
---

Registered keys now expire after 30 days. When a device signs a request with an expired key, the server answers `401 unknown_key`, and the client registers a new key and retries, so the device goes through the attestation checks again. Change the duration with the new `maxKeyAgeSeconds` option, or set it to `Infinity` to keep keys forever.

If you wrote your own store: key records now carry an `expiresAt`, after which you can delete them.
