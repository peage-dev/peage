# Péage RN Example

Minimal RN app exercising `@peage/react-native` against the `@peage/express`
example server, on a real iPhone or Android phone. Neither App Attest nor
Play Integrity works in a simulator or emulator.

## Both platforms

### Server

Start the express example from `examples/express`. The phone reaches it over
your LAN:

```sh
ipconfig getifaddr en0     # your laptop's LAN IP
```

The `DEFAULT_BASE_URL` in `App.tsx` is a placeholder LAN address that almost
certainly isn't yours. Set it to `http://<LAN_IP>:3000`, or override it at
runtime: type it in the on-screen input field and submit.

### Using the app

The app shows its version under the title. Tap **Attest** to register the
device's key with the server, then **Call /api/hello** to send a signed
request through the protected route. **Call unsigned** sends the same request
without Péage headers (the server answers 401), and **Reset** forgets the key
so the next request registers a new one. **Call gzip** POSTs a JSON body to
`/api/echo` with `Content-Encoding: gzip`: React Native compresses it after the
client signed it, and the server answers with the decoded body. The log pane
shows each step.

## iOS

### 1. Xcode

Open `ios/RNExample.xcworkspace` (after `pod install`, see step 3). Then:

The project ships with the maintainer's team and the Bundle Identifier
`dev.peage.RNExample`, which is registered to that team. In
**Signing & Capabilities**:

- Set **Team** to your own team.
- Change the **Bundle Identifier** to one of yours, e.g. `com.<you>.RNExample`.
- Keep the **App Attest** capability, already added
  (`com.apple.developer.devicecheck.appattest-environment: development`).

### 2. Server config

The server checks the attestation's rpIdHash against its configured `appId`.
Start the express example with `PEAGE_APP_ID` set to your iOS App ID
(`<10-char Team ID>.<Bundle Identifier>`), and `PEAGE_ENV=development`:
Xcode builds produce development-environment attestations, which a
production-mode server rejects.

```sh
cd ../express
PEAGE_ENV=development PEAGE_APP_ID="ABCDE12345.dev.peage.RNExample" pnpm start
```

### 3. Install pods and run

```sh
cd ios && bundle install && bundle exec pod install && cd ..
pnpm start                 # Metro
pnpm ios --device          # build + install on a tethered iPhone
```

## Android

Play Integrity only vouches for apps Google Play knows, so the app is
registered in Play Console as `dev.peage.rnexample` and installed from its
internal-testing track. The phone needs the Play Store and a Google account
that is an internal tester.

### 1. Play Console keys

In Play Console → **App integrity** → **Play Integrity API**, choose
self-managed response encryption keys and download them. The server needs:

- `PEAGE_ANDROID_PACKAGE`: `dev.peage.rnexample`
- `PEAGE_PLAY_INTEGRITY_DECRYPTION_KEY`: the base64 AES key
- `PEAGE_PLAY_INTEGRITY_VERIFICATION_KEY`: the base64 public key

Start the express example with those set and `PEAGE_ENV` unset (production
mode). The server downloads Google's attestation revocation list, so it needs
outbound HTTPS to `android.googleapis.com`.

### 2. Publish to internal testing

The Android SDK location comes from `ANDROID_HOME` or `android/local.properties`
(`sdk.dir=…`). From the repo root:

```sh
pnpm android:internal
```

It builds a release bundle with the next versionCode, uploads it and assigns
it to the internal track. It reads:

- `ORG_GRADLE_PROJECT_PEAGE_UPLOAD_STORE_FILE`, `…_STORE_PASSWORD`,
  `…_KEY_ALIAS`, `…_KEY_PASSWORD`: the upload keystore that signs the bundle
- `PEAGE_PLAY_SERVICE_ACCOUNT`: the JSON key of a service account allowed to
  release the app

Keep them out of the shell history, e.g. with 1Password references in
`android/.env` (gitignored) and `op run --env-file=examples/RNExample/android/.env -- pnpm android:internal`.

Install or update the app on the phone from the internal-testing link.

### Debug builds

`pnpm android` installs a debug build over adb. Play reports it as
`UNRECOGNIZED_VERSION`, which only a server started with
`PEAGE_ENV=development` accepts. Play's Automatic protection, on by default,
may also send a sideloaded app to the Play Store before it runs.

## What's wired

- `@peage/react-native` is workspace-linked. Metro follows pnpm's symlinks
  on its own; `metro.config.js` adds the workspace root to `watchFolders` and
  `nodeModulesPaths`.
- `App.tsx` calls `createPeageClient({ baseUrl })`. The Turbo Module is
  linked automatically on both platforms: App Attest and the Keychain on iOS,
  Play Integrity and the Android Keystore on Android.
- The native side passes the app version to `App` as an initial prop
  (`MainActivity.kt`, `SceneDelegate.swift`).
