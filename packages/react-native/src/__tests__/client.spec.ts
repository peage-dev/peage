import {
  fromBase64url,
  HTTP_HEADER_ASSERTION,
  HTTP_HEADER_KEY_ID,
  HTTP_HEADER_PROTOCOL_VERSION,
  PLATFORM_APP_ATTEST,
  PLATFORM_PLAY_INTEGRITY,
  type Platform,
  PROTOCOL_VERSION,
  toBase64url,
} from '@peage/protocol'
import { createHash } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { createPeageClientWithNative, type NativeAttest, PeageClientError } from '../testing.ts'

const BASE_URL = 'https://api.example.com'

function stubNative(overrides: Partial<NativeAttest> = {}): NativeAttest {
  const storedKeyIds = new Map<string, string>()
  return {
    isSupported: async () => true,
    generateKey: async () => 'GENERATED_KEY_ID',
    markAttested: async (keyId, scope) => {
      storedKeyIds.set(scope, keyId)
    },
    getKeyId: async (scope) => storedKeyIds.get(scope) ?? null,
    clearKeyId: async (scope) => {
      storedKeyIds.delete(scope)
    },
    attestKey: async () => 'ATTESTATION_PROOF',
    generateAssertion: async () => 'ASSERTION',
    // Same digest for every input; 8 characters is valid base64url.
    sha256: async () => 'STUBHASH',
    ...overrides,
  }
}

async function realSha256(data: string): Promise<string> {
  return toBase64url(createHash('sha256').update(fromBase64url(data)).digest())
}

const failingFetch: typeof fetch = async () => new Response(null, { status: 503 })

const captivePortal: typeof fetch = async () =>
  new Response('<html>Sign in to the Wi-Fi</html>', { status: 200 })

const offlineFetch: typeof fetch = async () => {
  throw new TypeError('Network request failed')
}

type Call = {
  url: string
  method: string | undefined
  credentials: RequestInit['credentials']
  body: string | undefined
  rawBody: Uint8Array | undefined
  headers: Headers
}

function urlOf(input: string | URL | Request): string {
  return input instanceof Request ? input.url : input.toString()
}

function recordingFetch(calls: Call[], solveStatus = 204): typeof fetch {
  return async (input, init) => {
    const url = urlOf(input)
    calls.push({
      url,
      method: init?.method,
      credentials: init?.credentials,
      body: typeof init?.body === 'string' ? init.body : undefined,
      rawBody: init?.body instanceof Uint8Array ? init.body : undefined,
      headers: new Headers(init?.headers),
    })
    if (url.endsWith('/peage/challenge')) {
      return Response.json({ challenge: 'CHALLENGE_VALUE' })
    }
    if (url.endsWith('/peage/solve')) {
      return new Response(null, { status: solveStatus })
    }
    return new Response('ok')
  }
}

function forgetfulFetch(forgottenKeyId: string, calls: Call[]): typeof fetch {
  const recording = recordingFetch(calls)
  return async (input, init) => {
    const response = await recording(input, init)
    if (new Headers(init?.headers).get(HTTP_HEADER_KEY_ID) !== forgottenKeyId) {
      return response
    }
    return new Response(null, {
      status: 401,
      headers: { 'WWW-Authenticate': 'Peage error="unknown_key"' },
    })
  }
}

function createClient(
  native: NativeAttest,
  fetchFromServer?: typeof fetch,
  platform: Platform = PLATFORM_APP_ATTEST,
) {
  return createPeageClientWithNative({
    baseUrl: BASE_URL,
    fetch: fetchFromServer,
    native,
    platform,
  })
}

async function expectClientError(promise: Promise<unknown>, code: string) {
  await expect(promise).rejects.toSatisfy(
    (error) => error instanceof PeageClientError && error.code === code,
  )
}

describe('register', () => {
  it('fetches a challenge, registers a new key and persists it', async () => {
    const native = stubNative()
    const calls: Call[] = []
    const peage = createClient(native, recordingFetch(calls))

    expect(await peage.register()).toBe('GENERATED_KEY_ID')

    expect(await native.getKeyId(BASE_URL)).toBe('GENERATED_KEY_ID')
    expect(calls.map((call) => call.url)).toStrictEqual([
      `${BASE_URL}/peage/challenge`,
      `${BASE_URL}/peage/solve`,
    ])
    expect(JSON.parse(calls[1]?.body ?? '')).toStrictEqual({
      challenge: 'CHALLENGE_VALUE',
      keyId: 'GENERATED_KEY_ID',
      platform: PLATFORM_APP_ATTEST,
      proof: 'ATTESTATION_PROOF',
    })
    expect(calls[0]?.headers.get(HTTP_HEADER_PROTOCOL_VERSION)).toBe(PROTOCOL_VERSION)
  })

  it('binds the new key and its attestation to SHA-256 of the challenge', async () => {
    const generateKey = vi.fn(async (_clientDataHash: string) => 'GENERATED_KEY_ID')
    const attestKey = vi.fn(async (_keyId: string, _clientDataHash: string) => 'ATTESTATION_PROOF')
    const native = stubNative({
      generateKey,
      attestKey,
      sha256: realSha256,
    })
    await createClient(native, recordingFetch([])).register()

    const challengeHash = toBase64url(createHash('sha256').update('CHALLENGE_VALUE').digest())
    expect(generateKey).toHaveBeenCalledWith(challengeHash, BASE_URL)
    expect(attestKey).toHaveBeenCalledWith('GENERATED_KEY_ID', challengeHash)
  })

  it('returns the stored keyId without contacting the server', async () => {
    const calls: Call[] = []
    const peage = createClient(
      stubNative({ getKeyId: async () => 'STORED' }),
      recordingFetch(calls),
    )
    expect(await peage.register()).toBe('STORED')
    expect(calls).toHaveLength(0)
  })

  it('shares one registration between concurrent callers', async () => {
    const generateKey = vi.fn(async () => 'GENERATED_KEY_ID')
    const peage = createClient(stubNative({ generateKey }), recordingFetch([]))
    await Promise.all([peage.register(), peage.register()])
    expect(generateKey).toHaveBeenCalledTimes(1)
  })

  it('shares the stored-key lookup too, so a late caller cannot start a second registration', async () => {
    const native = stubNative()
    const getKeyId = vi.spyOn(native, 'getKeyId')
    const peage = createClient(native, recordingFetch([]))
    await Promise.all([peage.register(), peage.register(), peage.register()])
    expect(getKeyId).toHaveBeenCalledTimes(1)
  })

  it("doesn't create a key when the challenge request fails", async () => {
    const generateKey = vi.fn(async () => 'GENERATED_KEY_ID')
    const peage = createClient(stubNative({ generateKey }), failingFetch)
    await expectClientError(peage.register(), 'SERVER')
    expect(generateKey).not.toHaveBeenCalled()
  })

  it.each([
    ['without a challenge', { token: 'CHALLENGE_VALUE' }],
    ['whose challenge is not a string', { challenge: 42 }],
  ])(
    "reports a challenge response %s as SERVER and doesn't create a key",
    async (_kind, challengeResponse) => {
      const generateKey = vi.fn(async () => 'GENERATED_KEY_ID')
      const peage = createClient(stubNative({ generateKey }), async (input) =>
        urlOf(input).endsWith('/peage/challenge')
          ? Response.json(challengeResponse)
          : new Response(null, { status: 204 }),
      )
      await expectClientError(peage.register(), 'SERVER')
      expect(generateKey).not.toHaveBeenCalled()
    },
  )

  it('reports a challenge answered with a web page, e.g. by a captive portal, as SERVER', async () => {
    await expectClientError(createClient(stubNative(), captivePortal).register(), 'SERVER')
  })

  it('reports an unreachable server as a network error', async () => {
    await expectClientError(createClient(stubNative(), offlineFetch).register(), 'NETWORK')
  })

  it('reports a challenge that expired before the solve as CHALLENGE_FAILED', async () => {
    const native = stubNative()
    const peage = createClient(native, async (input) => {
      if (urlOf(input).endsWith('/peage/challenge')) {
        return Response.json({ challenge: 'CHALLENGE_VALUE' })
      }
      return new Response(null, {
        status: 401,
        headers: { 'WWW-Authenticate': 'Peage error="unknown_challenge"' },
      })
    })
    await expectClientError(peage.register(), 'CHALLENGE_FAILED')
    expect(await native.getKeyId(BASE_URL)).toBeNull()
  })

  it("doesn't persist the keyId when the server rejects the attestation", async () => {
    const native = stubNative()
    const peage = createClient(native, recordingFetch([], 401))
    await expectClientError(peage.register(), 'ATTESTATION_REJECTED')
    expect(await native.getKeyId(BASE_URL)).toBeNull()
  })

  it.each([400, 413, 500])(
    'reports a %i from the solve as SERVER and stores no key',
    async (status) => {
      const native = stubNative()
      const peage = createClient(native, recordingFetch([], status))
      await expectClientError(peage.register(), 'SERVER')
      expect(await native.getKeyId(BASE_URL)).toBeNull()
    },
  )

  function nativeFailingFirstAttestation(code: string) {
    const attestedKeyIds: string[] = []
    const generateKey = vi.fn(async () => `KEY_${generateKey.mock.calls.length}`)
    const native = stubNative({
      generateKey,
      async attestKey(keyId) {
        attestedKeyIds.push(keyId)
        if (attestedKeyIds.length === 1) {
          throw Object.assign(new Error('attestation failed'), { code })
        }
        return 'ATTESTATION_PROOF'
      },
    })
    return { native, generateKey, attestedKeyIds }
  }

  it('retries the same key when Apple was unavailable during attestation', async () => {
    const { native, generateKey, attestedKeyIds } =
      nativeFailingFirstAttestation('E_SERVER_UNAVAILABLE')
    const peage = createClient(native, recordingFetch([]))

    await expectClientError(peage.register(), 'NATIVE')
    await peage.register()

    expect(generateKey).toHaveBeenCalledTimes(1)
    expect(attestedKeyIds).toStrictEqual(['KEY_1', 'KEY_1'])
  })

  it('generates a new key after clearKey once the retried key is registered', async () => {
    const { native, generateKey } = nativeFailingFirstAttestation('E_SERVER_UNAVAILABLE')
    const peage = createClient(native, recordingFetch([]))

    await expectClientError(peage.register(), 'NATIVE')
    await peage.register()
    await peage.clearKey()

    expect(await peage.register()).toBe('KEY_2')
    expect(generateKey).toHaveBeenCalledTimes(2)
  })

  it('generates a new key on Android after the server was unavailable during attestation', async () => {
    const { native, generateKey, attestedKeyIds } =
      nativeFailingFirstAttestation('E_SERVER_UNAVAILABLE')
    const peage = createClient(native, recordingFetch([]), PLATFORM_PLAY_INTEGRITY)

    await expectClientError(peage.register(), 'NATIVE')
    await peage.register()

    expect(generateKey).toHaveBeenCalledTimes(2)
    expect(attestedKeyIds).toStrictEqual(['KEY_1', 'KEY_2'])
  })

  it('generates a new key after any other attestation failure', async () => {
    const { native, generateKey, attestedKeyIds } =
      nativeFailingFirstAttestation('E_INTEGRITY_TOKEN')
    const peage = createClient(native, recordingFetch([]))

    await expectClientError(peage.register(), 'NATIVE')
    await peage.register()

    expect(generateKey).toHaveBeenCalledTimes(2)
    expect(attestedKeyIds).toStrictEqual(['KEY_1', 'KEY_2'])
  })

  it('refuses to register on a device without attestation support', async () => {
    const peage = createClient(stubNative({ isSupported: async () => false }), recordingFetch([]))
    await expectClientError(peage.register(), 'UNSUPPORTED')
  })
})

describe('isSupported', () => {
  it.each([false, true])('answers %s when the native module does', async (supported) => {
    const peage = createClient(stubNative({ isSupported: async () => supported }))
    expect(await peage.isSupported()).toBe(supported)
  })
})

describe('key scope', () => {
  function countingNative() {
    const generateKey = vi.fn(async () => `KEY_${generateKey.mock.calls.length}`)
    return { native: stubNative({ generateKey }), generateKey }
  }

  function clientWith(
    native: NativeAttest,
    options: { baseUrl?: string; keyScope?: string; fetch?: typeof fetch },
  ) {
    return createPeageClientWithNative({
      baseUrl: options.baseUrl ?? BASE_URL,
      keyScope: options.keyScope,
      fetch: options.fetch ?? recordingFetch([]),
      native,
      platform: PLATFORM_APP_ATTEST,
    })
  }

  it('stores the key under the normalized baseUrl', async () => {
    const { native } = countingNative()
    await clientWith(native, { baseUrl: 'HTTPS://API.example.com:443/v1/' }).register()
    expect(await native.getKeyId('https://api.example.com/v1')).toBe('KEY_1')
  })

  it('registers a separate key for each base path', async () => {
    const { native } = countingNative()
    await clientWith(native, { baseUrl: `${BASE_URL}/v1` }).register()
    await clientWith(native, { baseUrl: `${BASE_URL}/v2` }).register()
    expect(await native.getKeyId(`${BASE_URL}/v1`)).toBe('KEY_1')
    expect(await native.getKeyId(`${BASE_URL}/v2`)).toBe('KEY_2')
  })

  it('registers a separate key for each scope', async () => {
    const { native } = countingNative()
    await clientWith(native, { keyScope: 'payments' }).register()
    await clientWith(native, { keyScope: 'catalog' }).register()
    expect(await native.getKeyId('payments')).toBe('KEY_1')
    expect(await native.getKeyId('catalog')).toBe('KEY_2')
    expect(await native.getKeyId(BASE_URL)).toBeNull()
  })

  it('generates the key for keyScope rather than baseUrl', async () => {
    const { native, generateKey } = countingNative()
    await clientWith(native, { keyScope: 'payments' }).register()
    expect(generateKey).toHaveBeenCalledWith(expect.any(String), 'payments')
  })

  it('clearKey clears the keyScope key and keeps the key stored under baseUrl', async () => {
    const native = stubNative()
    await native.markAttested('BASE_URL_KEY_ID', BASE_URL)
    const peage = clientWith(native, { keyScope: 'payments' })
    await peage.register()

    await peage.clearKey()

    expect(await native.getKeyId('payments')).toBeNull()
    expect(await native.getKeyId(BASE_URL)).toBe('BASE_URL_KEY_ID')
  })

  it('replaces only the keyScope key when the server forgot it', async () => {
    const native = stubNative()
    await native.markAttested('FORGOTTEN_KEY_ID', 'payments')
    await native.markAttested('BASE_URL_KEY_ID', BASE_URL)
    const calls: Call[] = []
    const peage = clientWith(native, {
      keyScope: 'payments',
      fetch: forgetfulFetch('FORGOTTEN_KEY_ID', calls),
    })

    expect((await peage.fetch('/api/items')).status).toBe(200)

    expect(await native.getKeyId('payments')).toBe('GENERATED_KEY_ID')
    expect(await native.getKeyId(BASE_URL)).toBe('BASE_URL_KEY_ID')
  })

  it('shares one registration between clients of the same scope', async () => {
    const { native, generateKey } = countingNative()
    const [first, second] = await Promise.all([
      clientWith(native, {}).register(),
      clientWith(native, { baseUrl: 'HTTPS://API.example.com:443/' }).register(),
    ])
    expect(generateKey).toHaveBeenCalledTimes(1)
    expect(second).toBe(first)
  })

  it('shares the failed registration count between clients of the same scope', async () => {
    const native = stubNative()
    const rejected = createClient(native, recordingFetch([], 401))
    await expectRepeatedFailures(() => rejected.register(), 'ATTESTATION_REJECTED', 3)
    await expectClientError(
      createClient(native, recordingFetch([])).register(),
      'REGISTRATION_STOPPED',
    )
  })
})

async function signedPathAndFetchedUrl(baseUrl: string, input: string | URL | Request) {
  const signedHashes: string[] = []
  const native = stubNative({
    getKeyId: async () => 'KEY_ID',
    sha256: realSha256,
    async generateAssertion(_keyId, clientDataHash) {
      signedHashes.push(clientDataHash)
      return 'ASSERTION'
    },
  })
  const calls: Call[] = []
  const prefixed = createPeageClientWithNative({
    baseUrl,
    fetch: recordingFetch(calls),
    native,
    platform: PLATFORM_APP_ATTEST,
  })
  await prefixed.fetch(input)
  return { signedHash: signedHashes[0], fetchedUrl: calls[0]?.url, native }
}

async function hashSignedFor(native: NativeAttest, path: string): Promise<string | undefined> {
  const signedHashes: string[] = []
  const recording = {
    ...native,
    async generateAssertion(_keyId: string, clientDataHash: string) {
      signedHashes.push(clientDataHash)
      return 'ASSERTION'
    },
  }
  await createClient(recording, recordingFetch([])).fetch(path)
  return signedHashes[0]
}

describe('fetch path normalization', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2026-05-01T12:00:00Z'))
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it.each([
    ['/search/./results', '/search/results'],
    ['/a/b/../c', '/a/c'],
    ['/a/%2E%2e/c', '/c'],
    ['/a/b/..', '/a/'],
    ['/search?q=café', '/search?q=caf%C3%A9'],
    ['/a b', '/a%20b'],
    ['/items#top', '/items'],
    ['/a%zz', '/a%25zz'],
    ['/a"b{c}', '/a%22b%7Bc%7D'],
    ['/a\\b', '/a%5Cb'],
    ["/it's?q=it's", '/it%27s?q=it%27s'],
    ['/search/caf%C3%A9?q=a%20b&page=2', '/search/caf%C3%A9?q=a%20b&page=2'],
    ['/?', '/'],
    ['/items?', '/items'],
    ['/items?#top', '/items'],
    ['/items??', '/items??'],
    ['//x', '//x'],
    ['/a+b?q=a+b', '/a+b?q=a+b'],
    ['/a%2fb', '/a%2fb'],
    ['/😀', '/%F0%9F%98%80'],
    ['/\uD800', '/%EF%BF%BD'],
    ['/..', '/'],
    ['/a/../../b', '/b'],
    ['/a/b/.', '/a/b/'],
    ['/a/%2e', '/a/'],
    ['/a/%2E/b', '/a/b'],
    ['/a\tb', '/a%09b'],
    ['/a?b?c', '/a?b?c'],
  ])('sends and signs %s as %s', async (path, normalized) => {
    const { signedHash, fetchedUrl, native } = await signedPathAndFetchedUrl(BASE_URL, path)
    expect(fetchedUrl).toBe(`${BASE_URL}${normalized}`)
    expect(signedHash).toBe(await hashSignedFor(native, normalized))
  })

  it('sends the uppercased method it signs, which fetch would not do for PATCH', async () => {
    const calls: Call[] = []
    const peage = createClient(
      stubNative({ getKeyId: async () => 'KEY_ID' }),
      recordingFetch(calls),
    )
    await peage.fetch('/items/1', { method: 'patch', body: '{}' })
    expect(calls[0]?.method).toBe('PATCH')
  })

  it('refuses a path that does not start with /', async () => {
    const peage = createClient(stubNative({ getKeyId: async () => 'KEY_ID' }), recordingFetch([]))
    await expect(peage.fetch('items')).rejects.toThrow(/must start with \//)
  })
})

describe('fetch under a baseUrl with a path', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2026-05-01T12:00:00Z'))
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('signs the base path in front of the requested path', async () => {
    const { signedHash, fetchedUrl, native } = await signedPathAndFetchedUrl(
      `${BASE_URL}/v1`,
      '/items',
    )
    expect(fetchedUrl).toBe(`${BASE_URL}/v1/items`)
    expect(signedHash).toBe(await hashSignedFor(native, '/v1/items'))
  })

  it.each([
    ['/v 1', '/v%201/items'],
    ['/café', '/caf%C3%A9/items'],
    ['/v1/../v2', '/v2/items'],
  ])('normalizes a base path of %s with the requested path', async (basePath, normalized) => {
    const { signedHash, fetchedUrl, native } = await signedPathAndFetchedUrl(
      `${BASE_URL}${basePath}`,
      '/items',
    )
    expect(fetchedUrl).toBe(`${BASE_URL}${normalized}`)
    expect(signedHash).toBe(await hashSignedFor(native, normalized))
  })

  it('signs exactly the URL it sends when baseUrl ends with a slash', async () => {
    const { signedHash, fetchedUrl, native } = await signedPathAndFetchedUrl(
      `${BASE_URL}/v1/`,
      '/items',
    )
    expect(fetchedUrl).toBe(`${BASE_URL}/v1//items`)
    expect(signedHash).toBe(await hashSignedFor(native, '/v1//items'))
  })

  it.each(['api.example.com/v1', '/v1', 'ftp://api.example.com', 'https://api.example.com?v=1'])(
    'refuses a baseUrl of %s when the client is created',
    (baseUrl) => {
      expect(() =>
        createPeageClientWithNative({
          baseUrl,
          native: stubNative({}),
          platform: PLATFORM_APP_ATTEST,
        }),
      ).toThrow(/baseUrl must be an `http:\/\/` or `https:\/\/` URL/)
    },
  )
})

function callTo(calls: Call[], path: string): Call | undefined {
  return calls.find((call) => call.url === `${BASE_URL}${path}`)
}

describe('signing', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2026-05-01T12:00:00Z'))
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('sends the Péage headers from the native assertion', async () => {
    const calls: Call[] = []
    const peage = createClient(
      stubNative({ getKeyId: async () => 'KEY_ID' }),
      recordingFetch(calls),
    )
    await peage.fetch('/api/hello')
    const headers = callTo(calls, '/api/hello')?.headers
    expect(headers?.get(HTTP_HEADER_KEY_ID)).toBe('KEY_ID')
    expect(headers?.get(HTTP_HEADER_ASSERTION)).toBe('ASSERTION')
    expect(headers?.get(HTTP_HEADER_PROTOCOL_VERSION)).toBe(PROTOCOL_VERSION)
  })

  it('replaces Péage headers the caller supplied instead of adding to them', async () => {
    const calls: Call[] = []
    const peage = createClient(
      stubNative({ getKeyId: async () => 'KEY_ID' }),
      recordingFetch(calls),
    )
    await peage.fetch('/api/hello', {
      headers: {
        [HTTP_HEADER_KEY_ID]: 'CALLER_KEY_ID',
        [HTTP_HEADER_ASSERTION]: 'CALLER_ASSERTION',
        [HTTP_HEADER_PROTOCOL_VERSION]: 'CALLER_VERSION',
      },
    })
    const headers = callTo(calls, '/api/hello')?.headers
    expect(headers?.get(HTTP_HEADER_KEY_ID)).toBe('KEY_ID')
    expect(headers?.get(HTTP_HEADER_ASSERTION)).toBe('ASSERTION')
    expect(headers?.get(HTTP_HEADER_PROTOCOL_VERSION)).toBe(PROTOCOL_VERSION)
  })

  it('uppercases the method before signing so the server accepts it', async () => {
    const signedHashes: string[] = []
    const peage = createClient(
      stubNative({
        getKeyId: async () => 'KEY_ID',
        async generateAssertion(_keyId, clientDataHash) {
          signedHashes.push(clientDataHash)
          return 'ASSERTION'
        },
        sha256: realSha256,
      }),
      recordingFetch([]),
    )
    await peage.fetch('/x', { method: 'post', body: 'payload' })
    await peage.fetch('/x', { method: 'POST', body: 'payload' })
    await peage.fetch('/x', { method: 'PUT', body: 'payload' })
    expect(signedHashes[0]).toBe(signedHashes[1])
    expect(signedHashes[2]).not.toBe(signedHashes[1])
  })

  it('registers first when no keyId is stored yet', async () => {
    const attestKey = vi.fn(async () => 'ATTESTATION_PROOF')
    const peage = createClient(stubNative({ attestKey }), recordingFetch([]))
    await peage.fetch('/x')
    expect(attestKey).toHaveBeenCalledTimes(1)
  })

  it('replaces a key the OS invalidated and signs with the new one', async () => {
    let assertionCalls = 0
    const native = stubNative({
      async generateAssertion() {
        assertionCalls += 1
        if (assertionCalls === 1) {
          throw Object.assign(new Error('invalid key'), { code: 'E_INVALID_KEY' })
        }
        return 'FRESH_ASSERTION'
      },
    })
    await native.markAttested('DEAD_KEY_ID', BASE_URL)
    const calls: Call[] = []
    const peage = createClient(native, recordingFetch(calls))

    await peage.fetch('/x')

    const headers = callTo(calls, '/x')?.headers
    expect(headers?.get(HTTP_HEADER_KEY_ID)).toBe('GENERATED_KEY_ID')
    expect(headers?.get(HTTP_HEADER_ASSERTION)).toBe('FRESH_ASSERTION')
  })

  it('replaces an invalidated key once when two requests hit it together', async () => {
    const clearKeyId = vi.fn(async () => {})
    let storedKeyId: string | null = 'DEAD_KEY_ID'
    const native = stubNative({
      getKeyId: async () => storedKeyId,
      async clearKeyId() {
        await clearKeyId()
        storedKeyId = null
      },
      async markAttested(keyId) {
        storedKeyId = keyId
      },
      async generateAssertion(keyId) {
        if (keyId === 'DEAD_KEY_ID') {
          throw Object.assign(new Error('invalid key'), { code: 'E_INVALID_KEY' })
        }
        return 'FRESH_ASSERTION'
      },
    })
    const calls: Call[] = []
    const peage = createClient(native, recordingFetch(calls))

    await Promise.all([peage.fetch('/a'), peage.fetch('/b')])

    expect(
      ['/a', '/b'].map((path) => callTo(calls, path)?.headers.get(HTTP_HEADER_ASSERTION)),
    ).toStrictEqual(['FRESH_ASSERTION', 'FRESH_ASSERTION'])
    expect(clearKeyId).toHaveBeenCalledTimes(1)
    expect(storedKeyId).toBe('GENERATED_KEY_ID')
  })

  it('replaces an invalidated key after a failed attempt to forget it', async () => {
    const native = stubNative({
      async generateAssertion(keyId) {
        if (keyId === 'DEAD_KEY_ID') {
          throw Object.assign(new Error('invalid key'), { code: 'E_INVALID_KEY' })
        }
        return 'FRESH_ASSERTION'
      },
    })
    await native.markAttested('DEAD_KEY_ID', BASE_URL)
    vi.spyOn(native, 'clearKeyId').mockRejectedValueOnce(new Error('keychain unavailable'))
    const calls: Call[] = []
    const peage = createClient(native, recordingFetch(calls))

    await expectClientError(peage.fetch('/a'), 'NATIVE')
    await peage.fetch('/b')

    const headers = callTo(calls, '/b')?.headers
    expect(headers?.get(HTTP_HEADER_KEY_ID)).toBe('GENERATED_KEY_ID')
    expect(headers?.get(HTTP_HEADER_ASSERTION)).toBe('FRESH_ASSERTION')
  })

  it('reports other native failures without retrying', async () => {
    const generateAssertion = vi.fn(async () => {
      throw Object.assign(new Error('boom'), { code: 'E_ASSERT' })
    })
    const peage = createClient(
      stubNative({ getKeyId: async () => 'KEY_ID', generateAssertion }),
      recordingFetch([]),
    )
    await expectClientError(peage.fetch('/x'), 'NATIVE')
    expect(generateAssertion).toHaveBeenCalledTimes(1)
  })
})

async function expectRepeatedFailures(
  attempt: () => Promise<unknown>,
  code: string,
  times: number,
): Promise<void> {
  if (times === 0) {
    return
  }
  await expectClientError(attempt(), code)
  await expectRepeatedFailures(attempt, code, times - 1)
}

describe('clearKey', () => {
  it('clears a key whose registration was still in progress', async () => {
    const solve = Promise.withResolvers<Response>()
    const requestedUrls: string[] = []
    const native = stubNative()
    const peage = createClient(native, async (input) => {
      const url = urlOf(input)
      requestedUrls.push(url)
      if (url.endsWith('/peage/challenge')) {
        return Response.json({ challenge: 'CHALLENGE_VALUE' })
      }
      return url.endsWith('/peage/solve') ? solve.promise : new Response('ok')
    })

    const registration = peage.register()
    await vi.waitFor(() => expect(requestedUrls).toContain(`${BASE_URL}/peage/solve`))
    const clearing = peage.clearKey()
    solve.resolve(new Response(null, { status: 204 }))
    await registration
    await clearing

    expect(await native.getKeyId(BASE_URL)).toBeNull()
  })

  it('resolves after a registration in progress fails, and lets the next one reach the server', async () => {
    const solve = Promise.withResolvers<Response>()
    const requestedUrls: string[] = []
    const peage = createPeageClientWithNative({
      baseUrl: BASE_URL,
      fetch: async (input) => {
        const url = urlOf(input)
        requestedUrls.push(url)
        if (url.endsWith('/peage/challenge')) {
          return Response.json({ challenge: 'CHALLENGE_VALUE' })
        }
        return solve.promise
      },
      native: stubNative(),
      platform: PLATFORM_APP_ATTEST,
      maxRegistrationAttempts: 1,
    })

    const registration = peage.register()
    await vi.waitFor(() => expect(requestedUrls).toContain(`${BASE_URL}/peage/solve`))
    const clearing = peage.clearKey()
    solve.resolve(new Response(null, { status: 401 }))
    await expectClientError(registration, 'ATTESTATION_REJECTED')
    await expect(clearing).resolves.toBeUndefined()

    await expectClientError(peage.register(), 'ATTESTATION_REJECTED')
    expect(requestedUrls.filter((url) => url.endsWith('/peage/challenge'))).toHaveLength(2)
  })
})

describe('registration attempts', () => {
  function countingFetch(counts: { challenges: number }, solveStatus: number): typeof fetch {
    return async (input) => {
      const url = urlOf(input)
      if (url.endsWith('/peage/challenge')) {
        counts.challenges += 1
        return Response.json({ challenge: 'CHALLENGE_VALUE' })
      }
      if (url.endsWith('/peage/solve')) {
        return new Response(null, { status: solveStatus })
      }
      return new Response('ok')
    }
  }

  it('stops registering after 3 failures in a row by default', async () => {
    const counts = { challenges: 0 }
    const peage = createClient(stubNative(), countingFetch(counts, 401))
    await expectRepeatedFailures(() => peage.fetch('/api/items'), 'ATTESTATION_REJECTED', 3)
    await expectClientError(peage.fetch('/api/items'), 'REGISTRATION_STOPPED')
    expect(counts.challenges).toBe(3)
  })

  it('honours maxRegistrationAttempts', async () => {
    const counts = { challenges: 0 }
    const peage = createPeageClientWithNative({
      baseUrl: BASE_URL,
      fetch: countingFetch(counts, 500),
      native: stubNative(),
      platform: PLATFORM_APP_ATTEST,
      maxRegistrationAttempts: 1,
    })
    await expectClientError(peage.fetch('/api/items'), 'SERVER')
    await expectClientError(peage.fetch('/api/items'), 'REGISTRATION_STOPPED')
    expect(counts.challenges).toBe(1)
  })

  it('reports the last failure as the cause of REGISTRATION_STOPPED', async () => {
    let solveStatus = 401
    const peage = createPeageClientWithNative({
      baseUrl: BASE_URL,
      fetch: async (input) => {
        if (urlOf(input).endsWith('/peage/challenge')) {
          return Response.json({ challenge: 'CHALLENGE_VALUE' })
        }
        return new Response(null, { status: solveStatus })
      },
      native: stubNative(),
      platform: PLATFORM_APP_ATTEST,
      maxRegistrationAttempts: 2,
    })
    await expectClientError(peage.register(), 'ATTESTATION_REJECTED')
    solveStatus = 500
    const lastFailure = await peage.register().catch((error: unknown) => error)

    await expect(peage.register()).rejects.toSatisfy(
      (error) =>
        error instanceof PeageClientError &&
        error.code === 'REGISTRATION_STOPPED' &&
        error.cause === lastFailure,
    )
  })

  it("doesn't count an unsupported device as a failure", async () => {
    let isSupported = false
    const peage = createClient(
      stubNative({ isSupported: async () => isSupported }),
      recordingFetch([]),
    )
    await expectRepeatedFailures(() => peage.register(), 'UNSUPPORTED', 5)
    isSupported = true
    expect(await peage.register()).toBe('GENERATED_KEY_ID')
  })

  it("doesn't count failures while offline", async () => {
    const peage = createClient(stubNative(), offlineFetch)
    await expectRepeatedFailures(() => peage.register(), 'NETWORK', 5)
  })

  it('starts counting again after clearKey', async () => {
    const counts = { challenges: 0 }
    const peage = createClient(stubNative(), countingFetch(counts, 401))
    await expectRepeatedFailures(() => peage.register(), 'ATTESTATION_REJECTED', 3)
    await peage.clearKey()
    await expectClientError(peage.register(), 'ATTESTATION_REJECTED')
    expect(counts.challenges).toBe(4)
  })

  it('starts counting again after a successful registration', async () => {
    let solveStatus = 401
    const native = stubNative()
    const peage = createClient(native, async (input) => {
      const url = urlOf(input)
      if (url.endsWith('/peage/challenge')) {
        return Response.json({ challenge: 'CHALLENGE_VALUE' })
      }
      return new Response(null, { status: url.endsWith('/peage/solve') ? solveStatus : 200 })
    })
    await expectClientError(peage.register(), 'ATTESTATION_REJECTED')
    await expectClientError(peage.register(), 'ATTESTATION_REJECTED')
    solveStatus = 204
    await peage.register()
    await native.clearKeyId(BASE_URL)
    solveStatus = 401
    await expectRepeatedFailures(() => peage.register(), 'ATTESTATION_REJECTED', 3)
    await expectClientError(peage.register(), 'REGISTRATION_STOPPED')
  })
})

describe('fetch as a drop-in replacement', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2026-05-01T12:00:00Z'))
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  function realSha256Native() {
    return stubNative({
      getKeyId: async () => 'KEY_ID',
      sha256: realSha256,
    })
  }

  it.each([
    ['a full URL', `${BASE_URL}/items/../list?page=2`],
    ['a URL object', new URL(`${BASE_URL}/items/../list?page=2`)],
    ['a Request', new Request(`${BASE_URL}/items/../list?page=2`)],
  ])('signs and sends %s on the API server', async (_kind, input) => {
    const { signedHash, fetchedUrl, native } = await signedPathAndFetchedUrl(BASE_URL, input)
    expect(fetchedUrl).toBe(`${BASE_URL}/list?page=2`)
    expect(signedHash).toBe(await hashSignedFor(native, '/list?page=2'))
  })

  it.each([
    [`${BASE_URL}?page=2`, '/?page=2'],
    [`${BASE_URL}#top`, '/'],
    ['https://api.example.com:443/items', '/items'],
    ['HTTPS://API.EXAMPLE.COM/items', '/items'],
  ])('signs and sends %s as the path %s', async (input, path) => {
    const { signedHash, fetchedUrl, native } = await signedPathAndFetchedUrl(BASE_URL, input)
    expect(fetchedUrl).toBe(`${BASE_URL}${path}`)
    expect(signedHash).toBe(await hashSignedFor(native, path))
  })

  async function hashSignedBy(
    input: string | Request,
    init?: RequestInit,
  ): Promise<string | undefined> {
    const signedHashes: string[] = []
    const native = {
      ...realSha256Native(),
      async generateAssertion(_keyId: string, clientDataHash: string) {
        signedHashes.push(clientDataHash)
        return 'ASSERTION'
      },
    }
    await createClient(native, recordingFetch([])).fetch(input, init)
    return signedHashes[0]
  }

  const postInit = { method: 'POST', body: '{"name":"thing"}' }

  it("sends a Request's method, headers and body, and signs its body", async () => {
    const calls: Call[] = []
    const peage = createClient(realSha256Native(), recordingFetch(calls))
    await peage.fetch(
      new Request(`${BASE_URL}/api/items`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{"name":"thing"}',
      }),
    )
    const call = callTo(calls, '/api/items')
    expect(call?.method).toBe('POST')
    expect(call?.headers.get('content-type')).toBe('application/json')
    expect(call?.rawBody).toStrictEqual(new TextEncoder().encode('{"name":"thing"}'))
    expect(await hashSignedBy(new Request(`${BASE_URL}/api/items`, postInit))).toBe(
      await hashSignedBy('/api/items', postInit),
    )
  })

  it.each([
    'https://elsewhere.example.com/items',
    'http://api.example.com/items',
    'https://api.example.com:8443/items',
    'http://api.example.com:443/items',
    'https://api.example.com.elsewhere.example.com/items',
    'https://api.example.com@elsewhere.example.com/items',
    'https://elsewhere.example.com@api.example.com/items',
    'https://api.example.com\\@elsewhere.example.com/items',
    ' https://elsewhere.example.com/items',
    'javascript:alert(1)',
    'elsewhere.example.com/items',
    new URL('https://elsewhere.example.com/items'),
    new Request('https://elsewhere.example.com/items'),
  ])('refuses %s before signing anything', async (input) => {
    const calls: Call[] = []
    const generateAssertion = vi.fn(async () => 'ASSERTION')
    const peage = createClient({ ...realSha256Native(), generateAssertion }, recordingFetch(calls))
    await expect(peage.fetch(input)).rejects.toBeInstanceOf(TypeError)
    expect(calls).toStrictEqual([])
    expect(generateAssertion).not.toHaveBeenCalled()
  })

  it('sends and signs a null body as an empty body', async () => {
    const calls: Call[] = []
    const peage = createClient(realSha256Native(), recordingFetch(calls))
    await peage.fetch('/api/items', { method: 'POST', body: null })
    expect(callTo(calls, '/api/items')).toBeDefined()
    expect(await hashSignedBy('/api/items', { method: 'POST', body: null })).toBe(
      await hashSignedBy('/api/items', { method: 'POST' }),
    )
  })

  it('lets init replace the method, headers and body of a Request', async () => {
    const calls: Call[] = []
    const peage = createClient(realSha256Native(), recordingFetch(calls))
    await peage.fetch(
      new Request(`${BASE_URL}/api/items`, {
        method: 'POST',
        headers: { 'x-from-request': 'yes' },
        body: 'from request',
      }),
      { method: 'PUT', headers: { 'x-from-init': 'yes' }, body: 'from init' },
    )
    const call = callTo(calls, '/api/items')
    expect(call?.method).toBe('PUT')
    expect(call?.body).toBe('from init')
    expect(call?.headers.get('x-from-init')).toBe('yes')
    expect(call?.headers.has('x-from-request')).toBe(false)
  })

  it('forwards credentials', async () => {
    const calls: Call[] = []
    const peage = createClient(realSha256Native(), recordingFetch(calls))
    await peage.fetch('/api/items', { credentials: 'omit' })
    expect(callTo(calls, '/api/items')?.credentials).toBe('omit')
  })

  it("forwards a Request's signal and credentials", async () => {
    const request = new Request(`${BASE_URL}/api/items`, { credentials: 'omit' })
    let sentInit: RequestInit | undefined
    const peage = createClient(realSha256Native(), async (_input, init) => {
      sentInit = init
      return new Response('ok')
    })
    await peage.fetch(request)
    expect(sentInit?.signal).toBe(request.signal)
    expect(sentInit?.credentials).toBe('omit')
  })

  it('lets init replace the signal and credentials of a Request', async () => {
    const request = new Request(`${BASE_URL}/api/items`, {
      credentials: 'omit',
      signal: new AbortController().signal,
    })
    const initSignal = new AbortController().signal
    let sentInit: RequestInit | undefined
    const peage = createClient(realSha256Native(), async (_input, init) => {
      sentInit = init
      return new Response('ok')
    })
    await peage.fetch(request, { signal: initSignal, credentials: 'include' })
    expect(sentInit?.signal).toBe(initSignal)
    expect(sentInit?.credentials).toBe('include')
  })

  it('refuses a method that is not made of the letters A–Z with a TypeError', async () => {
    const generateAssertion = vi.fn(async () => 'ASSERTION')
    const peage = createClient({ ...realSha256Native(), generateAssertion }, recordingFetch([]))
    await expect(peage.fetch('/api/items', { method: 'M-SEARCH' })).rejects.toStrictEqual(
      new TypeError('Request method must be made of the letters A–Z'),
    )
    expect(generateAssertion).not.toHaveBeenCalled()
  })

  it("refuses an invalid init method before reading the Request's body", async () => {
    const request = new Request(`${BASE_URL}/api/items`, { method: 'POST', body: 'x' })
    const peage = createClient(realSha256Native(), recordingFetch([]))
    await expect(peage.fetch(request, { method: 'M-SEARCH' })).rejects.toStrictEqual(
      new TypeError('Request method must be made of the letters A–Z'),
    )
    expect(request.bodyUsed).toBe(false)
  })

  it('refuses the cache option, which React Native turns into a URL parameter', async () => {
    const peage = createClient(realSha256Native(), recordingFetch([]))
    await expect(peage.fetch('/api/items', { cache: 'no-store' })).rejects.toThrow(/cache/)
  })

  async function expectRefusedBeforeSigning(init: RequestInit, message: RegExp) {
    const calls: Call[] = []
    const generateAssertion = vi.fn(async () => 'ASSERTION')
    const peage = createClient({ ...realSha256Native(), generateAssertion }, recordingFetch(calls))
    await expect(peage.fetch('/api/items', { method: 'POST', ...init })).rejects.toThrow(
      expect.objectContaining({ name: 'TypeError', message: expect.stringMatching(message) }),
    )
    expect(calls).toStrictEqual([])
    expect(generateAssertion).not.toHaveBeenCalled()
  }

  it.each(['deflate', 'br', 'GZIP', 'gzip, br', 'gzip, gzip'])(
    'refuses Content-Encoding: %s, which iOS would send uncompressed, before signing',
    async (contentEncoding) => {
      await expectRefusedBeforeSigning(
        { headers: { 'content-encoding': contentEncoding }, body: 'payload' },
        /Content-Encoding other than lowercase `gzip`/,
      )
    },
  )

  it("refuses a Request's unsupported Content-Encoding before reading its body", async () => {
    const request = new Request(`${BASE_URL}/api/items`, {
      method: 'POST',
      headers: { 'content-encoding': 'br' },
      body: 'x',
    })
    const peage = createClient(realSha256Native(), recordingFetch([]))
    await expect(peage.fetch(request)).rejects.toThrow(
      /Content-Encoding other than lowercase `gzip`/,
    )
    expect(request.bodyUsed).toBe(false)
  })

  it.each(['identity', 'IDENTITY'])(
    'sends Content-Encoding: %s with the body unchanged',
    async (contentEncoding) => {
      const calls: Call[] = []
      const peage = createClient(realSha256Native(), recordingFetch(calls))
      await peage.fetch('/api/items', {
        method: 'POST',
        headers: { 'content-encoding': contentEncoding },
        body: 'payload',
      })
      const call = callTo(calls, '/api/items')
      expect(call?.headers.get('content-encoding')).toBe(contentEncoding)
      expect(call?.body).toBe('payload')
    },
  )

  it('sends a Uint8Array body with Content-Encoding: identity unchanged and signs it', async () => {
    const calls: Call[] = []
    const peage = createClient(realSha256Native(), recordingFetch(calls))
    const body = new TextEncoder().encode('{"name":"thing"}')
    const identityInit = { method: 'POST', headers: { 'content-encoding': 'identity' }, body }
    await peage.fetch('/api/items', identityInit)
    expect(callTo(calls, '/api/items')?.rawBody).toStrictEqual(body)
    expect(await hashSignedBy('/api/items', identityInit)).toBe(
      await hashSignedBy('/api/items', postInit),
    )
  })

  it('refuses Content-Encoding: gzip on a Uint8Array body before signing', async () => {
    await expectRefusedBeforeSigning(
      { headers: { 'content-encoding': 'gzip' }, body: new TextEncoder().encode('payload') },
      /`Content-Encoding: gzip` on bytes/,
    )
  })

  it.each([
    'text/plain; charset=ISO-8859-1',
    'text/plain; Charset=ISO-8859-1',
    'text/plain; charset="latin1"',
    'application/json; charset=utf-16',
    'text/plain; charset=utf-8; charset=ISO-8859-1',
  ])(
    'refuses a string body sent as %s, which Android encodes in that charset',
    async (contentType) => {
      await expectRefusedBeforeSigning(
        { headers: { 'content-type': contentType }, body: 'café' },
        /charset other than UTF-8/,
      )
    },
  )

  it.each([
    'text/plain; charset=utf-8',
    'text/plain;charset=UTF-8',
    'text/plain; charset="utf-8"',
    "text/plain; charset='UTF8'",
    'application/json',
  ])('sends a string body declared as %s', async (contentType) => {
    const calls: Call[] = []
    const peage = createClient(realSha256Native(), recordingFetch(calls))
    await peage.fetch('/api/items', {
      method: 'POST',
      headers: { 'content-type': contentType },
      body: 'café',
    })
    expect(callTo(calls, '/api/items')?.body).toBe('café')
  })

  it('sends a Uint8Array body whose Content-Type declares another charset, since its bytes are sent as is', async () => {
    const calls: Call[] = []
    const peage = createClient(realSha256Native(), recordingFetch(calls))
    const body = new TextEncoder().encode('café')
    await peage.fetch('/api/items', {
      method: 'POST',
      headers: { 'content-type': 'text/plain; charset=ISO-8859-1' },
      body,
    })
    expect(callTo(calls, '/api/items')?.rawBody).toStrictEqual(body)
  })

  it('sends a string body with Content-Encoding: gzip uncompressed and signs the uncompressed string', async () => {
    const calls: Call[] = []
    const peage = createClient(realSha256Native(), recordingFetch(calls))
    const gzipInit = {
      method: 'POST',
      headers: { 'content-encoding': 'gzip' },
      body: '{"name":"thing"}',
    }
    await peage.fetch('/api/items', gzipInit)
    const call = callTo(calls, '/api/items')
    expect(call?.headers.get('content-encoding')).toBe('gzip')
    expect(call?.body).toBe('{"name":"thing"}')
    expect(await hashSignedBy('/api/items', gzipInit)).toBe(
      await hashSignedBy('/api/items', postInit),
    )
  })

  it.each(['GET', 'HEAD'])('refuses a %s with a body before signing', async (method) => {
    const generateAssertion = vi.fn(async () => 'ASSERTION')
    const peage = createClient({ ...realSha256Native(), generateAssertion }, recordingFetch([]))
    await expect(peage.fetch('/api/items', { method, body: 'x' })).rejects.toThrow(
      `A ${method} request can't have a body`,
    )
    expect(generateAssertion).not.toHaveBeenCalled()
  })

  it('throws an AbortError without signing when the request was already aborted', async () => {
    const generateAssertion = vi.fn(async () => 'ASSERTION')
    const peage = createClient({ ...realSha256Native(), generateAssertion }, recordingFetch([]))
    const controller = new AbortController()
    controller.abort()
    await expect(peage.fetch('/api/items', { signal: controller.signal })).rejects.toMatchObject({
      name: 'AbortError',
    })
    expect(generateAssertion).not.toHaveBeenCalled()
  })

  it('throws the abort reason without signing when the request was already aborted with one', async () => {
    const generateAssertion = vi.fn(async () => 'ASSERTION')
    const peage = createClient({ ...realSha256Native(), generateAssertion }, recordingFetch([]))
    const controller = new AbortController()
    const reason = new Error('The user left the screen')
    controller.abort(reason)
    await expect(peage.fetch('/api/items', { signal: controller.signal })).rejects.toBe(reason)
    expect(generateAssertion).not.toHaveBeenCalled()
  })

  it('forwards the signal and passes a cancellation through unchanged', async () => {
    const controller = new AbortController()
    let sentSignal: AbortSignal | null | undefined
    const peage = createClient(realSha256Native(), async (_input, init) => {
      sentSignal = init?.signal
      controller.abort()
      throw controller.signal.reason
    })
    await expect(peage.fetch('/api/items', { signal: controller.signal })).rejects.toMatchObject({
      name: 'AbortError',
    })
    expect(sentSignal).toBe(controller.signal)
  })

  it('passes a timeout through unchanged', async () => {
    const timeout = new Error('The operation timed out')
    timeout.name = 'TimeoutError'
    const peage = createClient(realSha256Native(), async () => {
      throw timeout
    })
    await expect(peage.fetch('/api/items')).rejects.toBe(timeout)
  })

  it.each([
    ['//elsewhere.example.com/items', '//elsewhere.example.com/items'],
    ['/\\elsewhere.example.com/items', '/%5Celsewhere.example.com/items'],
    ['/%2F%2Felsewhere.example.com/items', '/%2F%2Felsewhere.example.com/items'],
    ['/a/../../elsewhere.example.com', '/elsewhere.example.com'],
  ])('keeps %s on the API server, as the path %s', async (input, path) => {
    const calls: Call[] = []
    const peage = createClient(realSha256Native(), recordingFetch(calls))
    await peage.fetch(input)
    expect(calls.map((call) => call.url)).toStrictEqual([`${BASE_URL}${path}`])
  })
})

describe('fetch', () => {
  it('signs the request and sends it to baseUrl + path with the caller headers', async () => {
    const calls: Call[] = []
    const peage = createClient(
      stubNative({ getKeyId: async () => 'KEY_ID' }),
      recordingFetch(calls),
    )

    const response = await peage.fetch('/api/items?page=2', {
      method: 'POST',
      body: '{"name":"thing"}',
      headers: { 'content-type': 'application/json' },
    })

    expect(await response.text()).toBe('ok')
    const [call] = calls
    if (!call) {
      throw new Error('fetch was not called')
    }
    const { headers } = call
    expect(call.url).toBe(`${BASE_URL}/api/items?page=2`)
    expect(call.body).toBe('{"name":"thing"}')
    expect(headers.get('content-type')).toBe('application/json')
    expect(headers.get(HTTP_HEADER_KEY_ID)).toBe('KEY_ID')
    expect(headers.get(HTTP_HEADER_ASSERTION)).toBe('ASSERTION')
  })

  it('registers a new key and retries once when the server forgot the key', async () => {
    const native = stubNative({ generateKey: async () => 'NEW_KEY_ID' })
    await native.markAttested('FORGOTTEN_KEY_ID', BASE_URL)
    const calls: Call[] = []
    const peage = createClient(native, forgetfulFetch('FORGOTTEN_KEY_ID', calls))

    const response = await peage.fetch('/api/items', { method: 'POST', body: '{"name":"thing"}' })

    expect(response.status).toBe(200)
    const apiCalls = calls.filter((call) => call.url === `${BASE_URL}/api/items`)
    expect(apiCalls.map((call) => call.headers.get(HTTP_HEADER_KEY_ID))).toStrictEqual([
      'FORGOTTEN_KEY_ID',
      'NEW_KEY_ID',
    ])
    expect(apiCalls.map((call) => call.body)).toStrictEqual([
      '{"name":"thing"}',
      '{"name":"thing"}',
    ])
  })

  it("doesn't retry other 401s", async () => {
    let requests = 0
    const fetchFromServer: typeof fetch = async () => {
      requests += 1
      return new Response(null, {
        status: 401,
        headers: { 'WWW-Authenticate': 'Peage error="invalid_signature"' },
      })
    }
    const peage = createClient(stubNative({ getKeyId: async () => 'KEY_ID' }), fetchFromServer)
    expect((await peage.fetch('/api/items')).status).toBe(401)
    expect(requests).toBe(1)
  })

  it('refuses bodies it cannot sign', async () => {
    const peage = createClient(stubNative({ getKeyId: async () => 'KEY_ID' }), recordingFetch([]))
    await expect(peage.fetch('/upload', { method: 'POST', body: new Blob(['x']) })).rejects.toThrow(
      /only sign string or Uint8Array/,
    )
  })
})
