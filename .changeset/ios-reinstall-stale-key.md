---
'@peage/react-native': patch
---

On iOS, the client no longer gets stuck after the app is deleted and reinstalled. The keyId was kept in the Keychain, which outlives the app, while its App Attest key doesn't, so every request failed with `NATIVE` (`cause.code` `E_INVALID_INPUT`) before reaching the server. The keyId now lives in UserDefaults, which is deleted with the app; one stored by an earlier version moves there on first use, so updating keeps the registered key. A stored keyId that iOS still rejects this way is replaced by registering once. Apps that catch `E_INVALID_INPUT`, call `clearKey()` and retry can drop that workaround on this version; it still works, but is no longer needed. The pod now ships a privacy manifest for its UserDefaults use (reason `CA92.1`).
