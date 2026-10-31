---
'@peage/react-native': minor
---

Generate one native assertion at a time per native module, so concurrent `fetch` calls no longer fail with App Attest's `DCError` 0; requests are still sent in parallel.
