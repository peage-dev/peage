import { HTTP_HEADER_DEBUG_TOKEN } from '@peage/protocol'
import { describe, expect, it, vi } from 'vitest'

import { createPeageClient, PeageClientError } from '../index.ts'

vi.mock('react-native', () => ({
  Platform: { OS: 'ios' },
  TurboModuleRegistry: { get: () => null },
}))

const BASE_URL = 'https://api.example.com'

function isUnlinkedModuleError(error: unknown): boolean {
  return (
    error instanceof PeageClientError &&
    error.code === 'UNSUPPORTED' &&
    /native module is not linked: rebuild the app/.test(error.message)
  )
}

describe('createPeageClient without the native module linked', () => {
  it('reports the device as unsupported', async () => {
    const peage = createPeageClient({ baseUrl: BASE_URL })
    expect(await peage.isSupported()).toBe(false)
  })

  it('refuses to register or fetch, saying the native module is not linked', async () => {
    const fetchFromServer = vi.fn<typeof fetch>(async () => new Response('ok'))
    const peage = createPeageClient({ baseUrl: BASE_URL, fetch: fetchFromServer })

    await expect(peage.register()).rejects.toSatisfy(isUnlinkedModuleError)
    await expect(peage.fetch('/x')).rejects.toSatisfy(isUnlinkedModuleError)
    expect(fetchFromServer).not.toHaveBeenCalled()
  })

  it('has no key to clear', async () => {
    const peage = createPeageClient({ baseUrl: BASE_URL })
    await expect(peage.clearKey()).resolves.toBeUndefined()
  })

  it('sends requests with the debug token', async () => {
    const fetchFromServer = vi.fn<typeof fetch>(async () => new Response('ok'))
    const peage = createPeageClient({
      baseUrl: BASE_URL,
      fetch: fetchFromServer,
      debugToken: 'DEBUG_TOKEN',
    })

    await peage.fetch('/x')

    const headers = new Headers(fetchFromServer.mock.calls[0]?.[1]?.headers)
    expect(headers.get(HTTP_HEADER_DEBUG_TOKEN)).toBe('DEBUG_TOKEN')
  })
})
