# Péage

TypeScript libraries that check requests to your API come from your iOS or
Android app, using Apple's App Attest and Google's Play Integrity. A React
Native client signs the requests and an Express middleware verifies them.

> **Pre-release.** Nothing is published to npm yet, and APIs may change before
> 0.1.

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
import { CHALLENGE_PATH, SOLVE_PATH, createPeage, verifiedRequestOf } from '@peage/express'
import { createMemoryStore } from '@peage/store-memory'
import express from 'express'

const peage = createPeage({
  appAttest: { appId: 'ABCDE12345.com.example.app' },
  playIntegrity: {
    packageName: 'com.example.app',
    decryptionKey: '<base64 key from Play Console>',
    verificationKey: '<base64 key from Play Console>',
  },
  store: createMemoryStore(), // @peage/store-redis in production
})

const app = express()
app.post(CHALLENGE_PATH, peage.challenge)
app.post(SOLVE_PATH, peage.solve)
app.get('/api/hello', peage.protect, (_req, res) => {
  res.json({ keyId: verifiedRequestOf(res).keyId })
})
```

Client:

```ts
import { createPeageClient } from '@peage/react-native'

const peage = createPeageClient({ baseUrl: 'https://api.example.com' })
const response = await peage.fetch('/api/hello')
```

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
