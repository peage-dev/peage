---
'@peage/react-native': patch
---

With `debugToken` set, `fetch` now always sends it instead of registering and signing, including on devices that can attest.
