---
'@peage/react-native': minor
---

`createPeageClient` no longer throws when the native module isn't linked, e.g. in Expo Go: `isSupported()` resolves false, and `register()` and `fetch()` reject with `UNSUPPORTED`, saying the native module isn't linked.
