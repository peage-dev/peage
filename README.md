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
0.88 with the New Architecture.

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

The client registers at `/peage/challenge` and `/peage/solve` under `baseUrl`,
where `peage.router` serves them. Set `challengePath` and `solvePath` if you
mount `peage.challenge` and `peage.solve` elsewhere.

In development, the same `debugToken` on `createPeage` and `createPeageClient`
lets devices that can't attest, such as the iOS simulator, through. `createPeage`
refuses it unless it is at least 32 characters and every configured platform
accepts development builds (App Attest `environment: 'development'`, Play
Integrity `allowUnrecognizedApps`). Android emulators with the Play Store count
as able to attest; use an image without Google Play.

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
