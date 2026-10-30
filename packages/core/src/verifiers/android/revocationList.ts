import type { X509Certificate } from 'node:crypto'

import type { LoadRevokedSerialNumbers } from '../../types.ts'
import type { RevocationList } from './types.ts'

import { assertValidRevocationList } from './asserters.ts'
import {
  GOOGLE_REVOCATION_LIST_URL,
  REVOCATION_LIST_LONGEST_REFRESH_MS,
  REVOCATION_LIST_MAX_STALE_MS,
  REVOCATION_LIST_REFRESH_MS,
  REVOCATION_LIST_RETRY_MS,
  REVOCATION_LIST_SHORTEST_RETRY_MS,
  REVOCATION_LIST_TIMEOUT_MS,
} from './constants.ts'

type DownloadedList = {
  serialNumbers: ReadonlySet<string>
  downloadedAt: number
  freshForMs: number
}

type DownloadFailure = {
  at: number
  error: unknown
  retryAfterMs: number
}

function freshForMs(response: Response): number {
  const maxAge = response.headers.get('cache-control')?.match(/max-age=(\d+)/)?.[1]
  if (maxAge === undefined) {
    return REVOCATION_LIST_REFRESH_MS
  }
  const age = Number(response.headers.get('age')) || 0
  const remainingMs = (Number(maxAge) - age) * 1000
  return Math.min(
    Math.max(remainingMs, REVOCATION_LIST_RETRY_MS),
    REVOCATION_LIST_LONGEST_REFRESH_MS,
  )
}

async function downloadRevocationList(fetchList: typeof fetch): Promise<DownloadedList> {
  const response = await fetchList(GOOGLE_REVOCATION_LIST_URL, {
    signal: AbortSignal.timeout(REVOCATION_LIST_TIMEOUT_MS),
  })
  if (!response.ok) {
    throw new Error(`Key attestation revocation list request failed (${response.status})`)
  }
  const body: unknown = await response.json()
  assertValidRevocationList(body)
  return {
    serialNumbers: new Set(Object.keys(body.entries)),
    downloadedAt: Date.now(),
    freshForMs: freshForMs(response),
  }
}

function unavailableError(cause: unknown): Error {
  return new Error('Key attestation revocation list is unavailable', { cause })
}

export function createGoogleRevocationList(
  fetchList: typeof fetch = fetch,
): LoadRevokedSerialNumbers {
  let downloaded: DownloadedList | undefined
  let refreshing: Promise<DownloadedList> | undefined
  let lastFailure: DownloadFailure | undefined

  function nextRetryAfterMs(): number {
    if (downloaded) {
      return REVOCATION_LIST_RETRY_MS
    }
    if (!lastFailure) {
      return REVOCATION_LIST_SHORTEST_RETRY_MS
    }
    return Math.min(lastFailure.retryAfterMs * 2, REVOCATION_LIST_RETRY_MS)
  }

  function refresh(): Promise<DownloadedList> {
    refreshing ??= downloadRevocationList(fetchList)
      .then((list) => {
        downloaded = list
        lastFailure = undefined
        return list
      })
      .catch((error: unknown) => {
        lastFailure = { at: Date.now(), error, retryAfterMs: nextRetryAfterMs() }
        throw error
      })
      .finally(() => {
        refreshing = undefined
      })
    return refreshing
  }

  function isRetryAllowed(): boolean {
    return !lastFailure || Date.now() - lastFailure.at > lastFailure.retryAfterMs
  }

  async function refreshOrFail(): Promise<ReadonlySet<string>> {
    if (!isRetryAllowed()) {
      throw unavailableError(lastFailure?.error)
    }
    try {
      return (await refresh()).serialNumbers
    } catch (error) {
      throw unavailableError(error)
    }
  }

  return async function loadRevokedSerialNumbers() {
    if (!downloaded) {
      return refreshOrFail()
    }
    const age = Date.now() - downloaded.downloadedAt
    if (age > downloaded.freshForMs + REVOCATION_LIST_MAX_STALE_MS) {
      return refreshOrFail()
    }
    if (age > downloaded.freshForMs && isRetryAllowed() && !refreshing) {
      refresh().catch((error: unknown) => {
        console.warn('[peage] Could not refresh the key attestation revocation list:', error)
      })
    }
    return downloaded.serialNumbers
  }
}

/** Google's spelling, Java's `BigInteger.toString(16)`; Node writes negative serials as `-7FFF`. */
export function revocationSerialOf(certificate: X509Certificate): string {
  const { serialNumber } = certificate
  const isNegative = serialNumber.startsWith('-')
  const magnitude = BigInt(`0x${isNegative ? serialNumber.slice(1) : serialNumber}`).toString(16)
  return isNegative ? `-${magnitude}` : magnitude
}

export function createRevocationList(load: LoadRevokedSerialNumbers): RevocationList {
  let latestList: ReadonlySet<string> | undefined
  let loading: Promise<ReadonlySet<string>> | undefined
  const warnings = new Set<string>()

  function warnOnce(message: string, error?: unknown): void {
    if (!warnings.has(message)) {
      warnings.add(message)
      console.warn(`[peage] ${message}`, error ?? '')
    }
  }

  function loadLatest(): Promise<ReadonlySet<string>> {
    loading ??= load()
      .then((list) => {
        latestList = list
        warnings.clear()
        return list
      })
      .finally(() => {
        loading = undefined
      })
    return loading
  }

  async function refreshInBackground(): Promise<void> {
    try {
      await loadLatest()
    } catch (error) {
      warnOnce('Could not load the key attestation revocation list', error)
    }
  }

  const firstLoad = refreshInBackground()

  async function latest(): Promise<ReadonlySet<string> | undefined> {
    if (!latestList) {
      await firstLoad
    }
    void refreshInBackground()
    if (!latestList) {
      warnOnce('No key attestation revocation list; signed requests skip the revocation check')
    }
    return latestList
  }

  return { load: loadLatest, latest }
}
