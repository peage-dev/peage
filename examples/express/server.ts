import {
  CHALLENGE_PATH,
  createPeage,
  type PlayIntegrityConfig,
  SOLVE_PATH,
  verifiedRequestOf,
} from '@peage/express'
import { createMemoryStore } from '@peage/store-memory'
import express, { type ErrorRequestHandler } from 'express'

// Local device testing only: accepts Xcode builds on iOS and adb-installed
// debug builds on Android. Leave PEAGE_ENV unset in production.
const isDevelopment = process.env.PEAGE_ENV === 'development'

// Android is enabled once all three Play Console values are set.
function playIntegrityFromEnv(): PlayIntegrityConfig | undefined {
  const packageName = process.env.PEAGE_ANDROID_PACKAGE
  const decryptionKey = process.env.PEAGE_PLAY_INTEGRITY_DECRYPTION_KEY
  const verificationKey = process.env.PEAGE_PLAY_INTEGRITY_VERIFICATION_KEY
  if (!packageName || !decryptionKey || !verificationKey) {
    return undefined
  }
  return { packageName, decryptionKey, verificationKey, allowUnrecognizedApps: isDevelopment }
}

const peage = createPeage({
  appAttest: {
    appId: process.env.PEAGE_APP_ID ?? 'ABCDE12345.dev.peage.example',
    environment: isDevelopment ? 'development' : 'production',
  },
  playIntegrity: playIntegrityFromEnv(),
  // Swap for `@peage/store-redis` or your own store in a real deployment.
  store: createMemoryStore(),
  onEvent: (event) =>
    console.log('[peage]', event.type, 'error' in event ? event.error.message : ''),
})

const app = express()

app.use((req, _res, next) => {
  console.log(`${req.method} ${req.path}`)
  next()
})

app.post(CHALLENGE_PATH, peage.challenge)
app.post(SOLVE_PATH, peage.solve)

app.get('/api/hello', peage.protect, (_req, res) => {
  const device = verifiedRequestOf(res)
  res.json({ message: `hello, ${device.platform} device ${device.keyId.slice(0, 8)}…` })
})

app.post('/api/echo', peage.protect, (req, res) => {
  res.json({ received: req.body, contentEncoding: req.header('content-encoding') ?? null })
})

const handleError: ErrorRequestHandler = (error, _req, res, _next) => {
  console.error(error)
  res.status(500).end()
}
app.use(handleError)

const port = Number(process.env.PORT ?? 3000)
app.listen(port, () => {
  console.log(`peage express example listening on http://localhost:${port}`)
})
