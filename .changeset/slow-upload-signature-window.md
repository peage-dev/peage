---
'@peage/core': patch
---

Measure a signed request's time window from when the server starts handling it, so a request whose body takes long to upload is no longer rejected as an invalid signature.
