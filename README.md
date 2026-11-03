<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/peage-lockup-on-dark.svg">
    <img alt="Péage" src="docs/assets/peage-lockup-on-light.svg" height="64">
  </picture>
</h1>

TypeScript libraries that check requests to your API come from your iOS or
Android app, using Apple's App Attest and Google's Play Integrity. A React
Native client signs the requests and an Express middleware verifies them.

> **0.x.** APIs may change between minor versions.

## Packages

| Package               | What it does                                                                  |
| --------------------- | ----------------------------------------------------------------------------- |
| `@peage/express`      | Express middleware: the registration endpoints and `protect` for your routes. |
| `@peage/core`         | The verifiers behind it, for writing other server adapters.                   |
| `@peage/react-native` | The client: registers the device's key and signs requests through `fetch`.    |
| `@peage/store-redis`  | Stores challenges and registered keys in Redis.                               |
| `@peage/store-memory` | An in-memory store for tests and local development.                           |
| `@peage/protocol`     | Constants and encodings shared by the client and the server.                  |

The server packages need Node.js 22.12 or later. The client needs React Native
0.76 or later with the New Architecture.

## Example

Server:

```ts
import { createPeage, verifiedRequestOf } from '@peage/express'
import { createMemoryStore } from '@peage/store-memory'
import express from 'express'

const peage = createPeage({
  appAttest: { appId: 'ABCDE12345.com.example.app' },
  playIntegrity: {
    packageName: 'com.example.app',
    decryptionKey: '<base64 key from Play Console>',
    verificationKey: '<base64 key from Play Console>',
  },
  store: createMemoryStore(), // createRedisStore({ redis: fromIoredis(client) }) in production
})

const app = express()
app.use(peage.router)
app.get('/api/hello', peage.protect, (_req, res) => {
  const request = verifiedRequestOf(res)
  res.json({ keyId: request.debug ? null : request.keyId })
})
```

Client:

```ts
import { createPeageClient } from '@peage/react-native'

const peage = createPeageClient({ baseUrl: 'https://api.example.com' })
const response = await peage.fetch('/api/hello')
```

The first time the app calls `fetch`, the client registers the device's key
through two endpoints, `/peage/challenge` and `/peage/solve`, which
`peage.router` serves. If you mount `peage.challenge` and `peage.solve`
somewhere else, point the client to them with `challengePath` and `solvePath`.

## Key expiry

A registered key is accepted for 30 days. After that, the server answers
`401 unknown_key`, and the client registers a new key and retries the request,
so the device goes through the attestation checks again. Change the duration
with `maxKeyAgeSeconds`, or set it to `Infinity` to keep keys forever.

Every Android registration uses one request from your Play Integrity quota,
which is 10,000 a day by default. With 30-day keys, expect about 1/30 of your
active Android devices to register again each day. A lifetime of a few minutes
means every active device registers again that often, which only works for a
small app or with a much larger quota. On iOS, Apple asks apps to stay under 100
attestations a second across all their users, and may throttle above that.

The Redis store deletes keys when they expire.

## Development builds

Simulators, and Android emulators, can't attest. To use them against your
server, give `createPeage` and `createPeageClient` the same `debugToken` in
development builds: the client then sends the token instead of registering and
signing. The server only accepts a token of at least 32 characters, and only
when every platform you configured accepts development builds
(`environment: 'development'` for App Attest, `allowUnrecognizedApps` for Play
Integrity), so a production server can't be set up with one.

## Development

```sh
pnpm install
pnpm test
pnpm build
```

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[MIT](LICENSE)
