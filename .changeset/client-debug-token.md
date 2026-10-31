---
'@peage/react-native': minor
---

Add a `debugToken` option for development: on a device that can't attest, e.g. a simulator or Expo Go, `fetch` sends it in `X-Peage-Debug-Token` instead of registering and signing. The server must be configured with the same token. Android emulators with the Play Store count as able to attest.
