import { fromBase64 } from '@peage/protocol'
import { certificateWithSerialNumber } from '@peage/tests'
import { X509Certificate } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  REVOCATION_LIST_LONGEST_REFRESH_MS,
  REVOCATION_LIST_MAX_STALE_MS,
  REVOCATION_LIST_REFRESH_MS,
  REVOCATION_LIST_RETRY_MS,
  REVOCATION_LIST_SHORTEST_RETRY_MS,
  REVOCATION_LIST_TIMEOUT_MS,
} from '../constants.ts'
import {
  createGoogleRevocationList,
  createRevocationList,
  revocationSerialOf,
} from '../revocationList.ts'
import { PIXEL_3A_KEY_ATTESTATION } from './deviceFixtures.ts'

const DAY_MS = 24 * 60 * 60 * 1000

function fetchUntilAborted(_input: unknown, init?: RequestInit): Promise<Response> {
  const { promise, reject } = Promise.withResolvers<Response>()
  const signal = init?.signal
  signal?.addEventListener('abort', () => reject(signal.reason))
  return promise
}

/** `AbortSignal.timeout` runs on Node's internal timers, which Vitest's fake timers don't drive. */
function abortSignalOnFakeTimeout(milliseconds: number): AbortSignal {
  const controller = new AbortController()
  setTimeout(() => controller.abort(new DOMException('Timed out', 'TimeoutError')), milliseconds)
  return controller.signal
}

function listing(serialNumbers: string[], headers: Record<string, string> = {}): Response {
  const entries = Object.fromEntries(
    serialNumbers.map((serial) => [serial, { status: 'REVOKED', reason: 'KEY_COMPROMISE' }]),
  )
  return Response.json({ entries }, { headers })
}

describe('createGoogleRevocationList', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.spyOn(console, 'warn').mockImplementation(() => undefined)
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('downloads the list once and reuses it while it is fresh', async () => {
    const fetchList = vi.fn<typeof fetch>(async () => listing(['abc']))
    const load = createGoogleRevocationList(fetchList)

    expect(await load()).toStrictEqual(new Set(['abc']))
    vi.advanceTimersByTime(REVOCATION_LIST_REFRESH_MS - 1)
    expect(await load()).toStrictEqual(new Set(['abc']))
    expect(fetchList).toHaveBeenCalledTimes(1)
  })

  it("keeps the list fresh for as long as Google's Cache-Control allows", async () => {
    const fetchList = vi.fn<typeof fetch>(async () =>
      listing(['abc'], { 'cache-control': 'public, max-age=86400' }),
    )
    const load = createGoogleRevocationList(fetchList)

    await load()
    vi.advanceTimersByTime(DAY_MS - 1)
    await load()
    expect(fetchList).toHaveBeenCalledTimes(1)
  })

  it('counts the time the response already spent in a cache', async () => {
    const fetchList = vi.fn<typeof fetch>(async () =>
      listing(['abc'], { 'cache-control': 'public, max-age=86400', age: '82800' }),
    )
    const load = createGoogleRevocationList(fetchList)

    await load()
    vi.advanceTimersByTime(60 * 60 * 1000 + 1)
    await load()
    await vi.waitFor(() => expect(fetchList).toHaveBeenCalledTimes(2))
  })

  it('keeps a response already older than its max-age fresh for the retry interval', async () => {
    const fetchList = vi.fn<typeof fetch>(async () =>
      listing(['abc'], { 'cache-control': 'public, max-age=86400', age: '90000' }),
    )
    const load = createGoogleRevocationList(fetchList)

    await load()
    vi.advanceTimersByTime(REVOCATION_LIST_RETRY_MS - 1)
    await load()
    expect(fetchList).toHaveBeenCalledTimes(1)

    vi.advanceTimersByTime(2)
    await load()
    await vi.waitFor(() => expect(fetchList).toHaveBeenCalledTimes(2))
  })

  it('refreshes a list with a very long max-age after the longest refresh interval', async () => {
    const fetchList = vi.fn<typeof fetch>(async () =>
      listing(['abc'], { 'cache-control': 'public, max-age=31536000' }),
    )
    const load = createGoogleRevocationList(fetchList)

    await load()
    vi.advanceTimersByTime(REVOCATION_LIST_LONGEST_REFRESH_MS - 1)
    await load()
    expect(fetchList).toHaveBeenCalledTimes(1)

    vi.advanceTimersByTime(2)
    await load()
    await vi.waitFor(() => expect(fetchList).toHaveBeenCalledTimes(2))
  })

  it('gives up on a download that takes longer than the timeout', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setTimeout'] })
    vi.spyOn(AbortSignal, 'timeout').mockImplementation(abortSignalOnFakeTimeout)
    const load = createGoogleRevocationList(fetchUntilAborted)

    const loading = load()
    vi.advanceTimersByTime(REVOCATION_LIST_TIMEOUT_MS)
    await expect(loading).rejects.toThrow(/revocation list is unavailable/)
  })

  it('shares one download between concurrent first calls', async () => {
    const fetchList = vi.fn<typeof fetch>(async () => listing(['abc']))
    const load = createGoogleRevocationList(fetchList)

    await Promise.all([load(), load(), load()])
    expect(fetchList).toHaveBeenCalledTimes(1)
  })

  it('serves the current list while refreshing a stale one', async () => {
    const fetchList = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(listing(['abc']))
      .mockResolvedValueOnce(listing(['abc', 'def']))
    const load = createGoogleRevocationList(fetchList)

    await load()
    vi.advanceTimersByTime(REVOCATION_LIST_REFRESH_MS + 1)
    expect(await load()).toStrictEqual(new Set(['abc']))
    await vi.waitFor(async () => expect(await load()).toStrictEqual(new Set(['abc', 'def'])))
  })

  it('waits before retrying a failed background refresh', async () => {
    const fetchList = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(listing(['abc']))
      .mockRejectedValue(new Error('offline'))
    const load = createGoogleRevocationList(fetchList)

    await load()
    vi.advanceTimersByTime(REVOCATION_LIST_REFRESH_MS + 1)
    await load()
    await vi.waitFor(() => expect(console.warn).toHaveBeenCalledTimes(1))

    await load()
    await load()
    expect(fetchList).toHaveBeenCalledTimes(2)

    vi.advanceTimersByTime(REVOCATION_LIST_RETRY_MS + 1)
    await load()
    expect(fetchList).toHaveBeenCalledTimes(3)
  })

  it('warns once for a failed background refresh shared by many calls', async () => {
    const failedRefresh = Promise.withResolvers<Response>()
    const fetchList = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(listing(['abc']))
      .mockReturnValueOnce(failedRefresh.promise)
    const load = createGoogleRevocationList(fetchList)

    await load()
    vi.advanceTimersByTime(REVOCATION_LIST_REFRESH_MS + 1)
    await Promise.all([load(), load(), load()])
    failedRefresh.reject(new Error('offline'))

    await vi.waitFor(() => expect(console.warn).toHaveBeenCalledTimes(1))
    await load()
    expect(console.warn).toHaveBeenCalledTimes(1)
  })

  it("keeps a stale list for up to a day while Google can't be reached", async () => {
    const fetchList = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(listing(['abc']))
      .mockRejectedValue(new Error('offline'))
    const load = createGoogleRevocationList(fetchList)

    await load()
    vi.advanceTimersByTime(REVOCATION_LIST_REFRESH_MS + REVOCATION_LIST_MAX_STALE_MS - 1)
    expect(await load()).toStrictEqual(new Set(['abc']))

    vi.advanceTimersByTime(REVOCATION_LIST_RETRY_MS + 2)
    await expect(load()).rejects.toThrow(/revocation list is unavailable/)
  })

  it('accepts a negative serial, spelled the way revocationSerialOf spells it', async () => {
    const load = createGoogleRevocationList(async () => listing(['abc', '-7fff']))
    const serial = revocationSerialOf(certificateWithSerialNumber(Uint8Array.of(0x80, 0x01)))
    expect((await load()).has(serial)).toBe(true)
  })

  it('rejects an error response even when its body reads as a list', async () => {
    const load = createGoogleRevocationList(
      async () => new Response('{"entries":{}}', { status: 503 }),
    )
    await expect(load()).rejects.toThrow(/revocation list is unavailable/)
  })

  it('fails without downloading again right after a failed first download', async () => {
    const fetchList = vi.fn<typeof fetch>(async () => new Response('', { status: 503 }))
    const load = createGoogleRevocationList(fetchList)

    await expect(load()).rejects.toThrow(/revocation list is unavailable/)
    await expect(load()).rejects.toThrow(/revocation list is unavailable/)
    expect(fetchList).toHaveBeenCalledTimes(1)
  })

  it('downloads again shortly after a failed first download', async () => {
    const fetchList = vi
      .fn<typeof fetch>()
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValue(listing(['abc']))
    const load = createGoogleRevocationList(fetchList)

    await expect(load()).rejects.toThrow(/revocation list is unavailable/)
    vi.advanceTimersByTime(REVOCATION_LIST_SHORTEST_RETRY_MS + 1)
    expect(await load()).toStrictEqual(new Set(['abc']))
    expect(fetchList).toHaveBeenCalledTimes(2)
  })

  it('doubles the wait after each failed first download', async () => {
    const fetchList = vi.fn<typeof fetch>().mockRejectedValue(new Error('offline'))
    const load = createGoogleRevocationList(fetchList)

    await expect(load()).rejects.toThrow(/revocation list is unavailable/)
    vi.advanceTimersByTime(REVOCATION_LIST_SHORTEST_RETRY_MS + 1)
    await expect(load()).rejects.toThrow(/revocation list is unavailable/)
    expect(fetchList).toHaveBeenCalledTimes(2)

    vi.advanceTimersByTime(REVOCATION_LIST_SHORTEST_RETRY_MS + 1)
    await expect(load()).rejects.toThrow(/revocation list is unavailable/)
    expect(fetchList).toHaveBeenCalledTimes(2)

    vi.advanceTimersByTime(REVOCATION_LIST_SHORTEST_RETRY_MS)
    await expect(load()).rejects.toThrow(/revocation list is unavailable/)
    expect(fetchList).toHaveBeenCalledTimes(3)
  })

  it('never waits longer than the retry interval for a first download', async () => {
    const fetchList = vi.fn<typeof fetch>().mockRejectedValue(new Error('offline'))
    const load = createGoogleRevocationList(fetchList)

    await expect(load()).rejects.toThrow(/revocation list is unavailable/)
    for (let attempt = 0; attempt < 20; attempt++) {
      vi.advanceTimersByTime(REVOCATION_LIST_RETRY_MS + 1)
      // oxlint-disable-next-line no-await-in-loop
      await expect(load()).rejects.toThrow(/revocation list is unavailable/)
    }
    expect(fetchList).toHaveBeenCalledTimes(21)
  })

  it('waits the full retry interval after a failed refresh once a list exists', async () => {
    const fetchList = vi
      .fn<typeof fetch>()
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce(listing(['abc']))
      .mockRejectedValue(new Error('offline'))
    const load = createGoogleRevocationList(fetchList)

    await expect(load()).rejects.toThrow(/revocation list is unavailable/)
    vi.advanceTimersByTime(REVOCATION_LIST_SHORTEST_RETRY_MS + 1)
    await load()
    vi.advanceTimersByTime(REVOCATION_LIST_REFRESH_MS + 1)
    await load()
    await vi.waitFor(() => expect(console.warn).toHaveBeenCalledTimes(1))
    expect(fetchList).toHaveBeenCalledTimes(3)

    vi.advanceTimersByTime(REVOCATION_LIST_SHORTEST_RETRY_MS * 4)
    await load()
    expect(fetchList).toHaveBeenCalledTimes(3)

    vi.advanceTimersByTime(REVOCATION_LIST_RETRY_MS)
    await load()
    expect(fetchList).toHaveBeenCalledTimes(4)
  })

  it.each([
    ['no entries', { revoked: [] }],
    ['entries as an empty array', { entries: [] }],
    ['a serial number with a leading zero', { entries: { '0abc': { status: 'REVOKED' } } }],
    ['an uppercase serial number', { entries: { ABC: { status: 'REVOKED' } } }],
  ])('rejects a list with %s', async (_shape, body) => {
    const load = createGoogleRevocationList(async () => Response.json(body))
    await expect(load()).rejects.toThrow(/revocation list is unavailable/)
  })
})

describe('revocationSerialOf', () => {
  it("spells serials the way Google's list does: lowercase, no leading zeros", () => {
    // The Pixel 3a's second intermediate has a serial with a leading zero.
    const der = fromBase64(PIXEL_3A_KEY_ATTESTATION.certificateChain[2] ?? '')
    const intermediate = new X509Certificate(der)
    expect(intermediate.serialNumber).toBe('038826676065899685F6')
    expect(revocationSerialOf(intermediate)).toBe('38826676065899685f6')
  })

  it('keeps the sign of a negative serial, as Java does', () => {
    const certificate = certificateWithSerialNumber(Uint8Array.of(0x80, 0x01))
    expect(certificate.serialNumber).toBe('-7FFF')
    expect(revocationSerialOf(certificate)).toBe('-7fff')
  })
})

describe('createRevocationList', () => {
  beforeEach(() => {
    vi.spyOn(console, 'warn').mockImplementation(() => undefined)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('starts loading as soon as it is created', () => {
    const load = vi.fn(async () => new Set(['abc']))
    createRevocationList(load)
    expect(load).toHaveBeenCalledTimes(1)
  })

  it('runs one load at a time', async () => {
    const firstLoad = Promise.withResolvers<ReadonlySet<string>>()
    const load = vi
      .fn<() => Promise<ReadonlySet<string>>>()
      .mockReturnValueOnce(firstLoad.promise)
      .mockResolvedValue(new Set(['abc']))
    const revocationList = createRevocationList(load)

    const loads = [revocationList.load(), revocationList.load()]
    expect(load).toHaveBeenCalledTimes(1)
    firstLoad.resolve(new Set(['abc']))
    expect(await Promise.all(loads)).toStrictEqual([new Set(['abc']), new Set(['abc'])])
  })

  it('waits for the first load only', async () => {
    const firstLoad = Promise.withResolvers<ReadonlySet<string>>()
    const load = vi
      .fn<() => Promise<ReadonlySet<string>>>()
      .mockReturnValueOnce(firstLoad.promise)
      .mockReturnValue(new Promise(() => undefined))
    const revocationList = createRevocationList(load)

    const duringFirstLoad = revocationList.latest()
    firstLoad.resolve(new Set(['abc']))
    expect(await duringFirstLoad).toStrictEqual(new Set(['abc']))
    expect(await revocationList.latest()).toStrictEqual(new Set(['abc']))
  })

  it('has no list when the first load failed, and warns once per problem', async () => {
    const revocationList = createRevocationList(async () => {
      throw new Error('offline')
    })
    expect(await revocationList.latest()).toBeUndefined()
    expect(await revocationList.latest()).toBeUndefined()
    expect(console.warn).toHaveBeenCalledTimes(2)
  })

  it('keeps serving the last list once loading fails, and warns once', async () => {
    const load = vi
      .fn<() => Promise<ReadonlySet<string>>>()
      .mockResolvedValueOnce(new Set(['abc']))
      .mockRejectedValue(new Error('offline'))
    const revocationList = createRevocationList(load)

    expect(await revocationList.latest()).toStrictEqual(new Set(['abc']))
    await vi.waitFor(() => expect(console.warn).toHaveBeenCalledTimes(1))
    expect(await revocationList.latest()).toStrictEqual(new Set(['abc']))
    await vi.waitFor(() => expect(load).toHaveBeenCalledTimes(3))
    expect(console.warn).toHaveBeenCalledTimes(1)
  })
})
