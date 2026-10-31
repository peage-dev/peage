---
'@peage/core': patch
---

A signed request whose stored key record holds a public key that can't be imported is now rejected as an unknown key (`401`, `unknown_key`), so the client registers again, instead of failing as a server error.
