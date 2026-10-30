import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'

import {
  assertCanonicalRequest,
  assertionBucket,
  canonicalRequestBytes,
  concatBytes,
  formatAuthenticateHeader,
  fromBase64,
  fromBase64url,
  isRecord,
  parseAuthenticateError,
  toBase64,
  toBase64url,
} from '../index.ts'

function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest())
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex')
}

function clientDataHash(request: { bucket: number; method: string; path: string; body: string }) {
  const bodyDigest = sha256(new TextEncoder().encode(request.body))
  return sha256(canonicalRequestBytes({ ...request, bodyDigest }))
}

describe('assertionBucket', () => {
  it('floors to a 30-second window', () => {
    expect(assertionBucket(0)).toBe(0)
    expect(assertionBucket(29)).toBe(0)
    expect(assertionBucket(30)).toBe(30)
    expect(assertionBucket(59)).toBe(30)
    expect(assertionBucket(1779742951)).toBe(1779742950)
  })
})

describe('canonicalRequestBytes', () => {
  it('matches the golden digest of the canonical signing string', () => {
    const hash = clientDataHash({
      body: '{"hello":"world"}',
      bucket: 1779742950,
      method: 'POST',
      path: '/api/things?id=42',
    })
    expect(hex(hash)).toBe('d36d384f2a6f06fa0355b7c5e1b048e29072594a3a157f98820ad6892f076d41')
  })

  it('lays out the tag, bucket, method and path on separate lines before the body digest', () => {
    const bodyDigest = sha256(new Uint8Array())
    const bytes = canonicalRequestBytes({
      bucket: 1779742950,
      bodyDigest,
      method: 'GET',
      path: '/',
    })
    const prefix = new TextEncoder().encode('peage-request-v1\n1779742950\nGET\n/\n')
    expect(bytes).toStrictEqual(concatBytes(prefix, bodyDigest))
  })

  it('differs when any one canonical input changes', () => {
    const base = { body: 'payload', bucket: 1779742950, method: 'POST', path: '/api' }
    const baseHash = hex(clientDataHash(base))
    expect(hex(clientDataHash({ ...base, bucket: 1779742980 }))).not.toBe(baseHash)
    expect(hex(clientDataHash({ ...base, method: 'GET' }))).not.toBe(baseHash)
    expect(hex(clientDataHash({ ...base, path: '/api/x' }))).not.toBe(baseHash)
    expect(hex(clientDataHash({ ...base, body: 'payload!' }))).not.toBe(baseHash)
  })
})

describe('assertCanonicalRequest', () => {
  it.each(['post', 'Get', 'GET\n', 'GET /x', 'M-SEARCH'])(
    'throws a TypeError for the method %j, which is not made of the letters A–Z only',
    (method) => {
      expect(() => assertCanonicalRequest({ method, path: '/' })).toThrow(
        new TypeError('Request method must be made of the letters A–Z'),
      )
    },
  )

  it.each([
    ['a line feed', '/a\n/b'],
    ['a carriage return', '/a\r/b'],
  ])('throws a TypeError for a path containing %s', (_character, path) => {
    expect(() => assertCanonicalRequest({ method: 'GET', path })).toThrow(
      new TypeError('Request path must not contain CR or LF'),
    )
  })
})

describe('base64 helpers', () => {
  const bytes = Uint8Array.of(0xfb, 0xff, 0x00, 0x10)

  it('round-trips standard base64 with padding', () => {
    expect(toBase64(bytes)).toBe('+/8AEA==')
    expect(fromBase64('+/8AEA==')).toStrictEqual(bytes)
  })

  it('round-trips base64url without padding', () => {
    expect(toBase64url(bytes)).toBe('-_8AEA')
    expect(fromBase64url('-_8AEA')).toStrictEqual(bytes)
  })

  it('round-trips base64url across a range of lengths without +, / or =', () => {
    for (const length of [0, 1, 2, 3, 16, 31, 32, 33, 64, 256]) {
      const original = crypto.getRandomValues(new Uint8Array(length))
      const encoded = toBase64url(original)
      expect(encoded).not.toMatch(/[+/=]/)
      expect(fromBase64url(encoded)).toStrictEqual(original)
    }
  })

  it('encodes large inputs', () => {
    expect(toBase64(new Uint8Array(2 * 1024 * 1024)).length).toBe(2796204)
  })
})

describe('isRecord', () => {
  it('is true for an object and false for an array or null', () => {
    expect(isRecord({ entries: [] })).toBe(true)
    expect(isRecord([])).toBe(false)
    expect(isRecord(null)).toBe(false)
  })
})

describe('WWW-Authenticate', () => {
  it('formats the scheme alone or with an error', () => {
    expect(formatAuthenticateHeader()).toBe('Peage')
    expect(formatAuthenticateHeader('unknown_key')).toBe('Peage error="unknown_key"')
  })

  it('reads the error back, and nothing from other schemes', () => {
    expect(parseAuthenticateError('Peage error="unknown_key"')).toBe('unknown_key')
    expect(parseAuthenticateError('Peage')).toBeUndefined()
    expect(parseAuthenticateError('Bearer error="unknown_key"')).toBeUndefined()
    expect(parseAuthenticateError(null)).toBeUndefined()
  })
})
