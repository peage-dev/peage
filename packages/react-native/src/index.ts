import { PLATFORM_APP_ATTEST, PLATFORM_PLAY_INTEGRITY } from '@peage/protocol'
import { Platform as ReactNativePlatform } from 'react-native'

import type { PeageClient, PeageClientOptions } from './types.ts'

import { createPeageClientWithNative } from './client.ts'
import NativePeageAttest from './NativePeageAttest.ts'
import { unlinkedNativeAttest } from './unlinkedNativeAttest.ts'

export { PeageClientError } from './errors.ts'
export type { PeageClient, PeageClientErrorCode, PeageClientOptions } from './types.ts'

/**
 * The Péage client: App Attest on iOS, Play Integrity on Android. When the native module isn't
 * linked, e.g. in Expo Go, `isSupported()` resolves false, `register()` rejects with UNSUPPORTED,
 * and so does `fetch()` unless `debugToken` is set. Throws a `TypeError` if `baseUrl` isn't an
 * `http://` or `https://` URL whose path, if any, starts with `/`, or if `challengePath` or
 * `solvePath` isn't a path starting with `/` or a URL on `baseUrl`'s origin.
 */
export function createPeageClient(options: PeageClientOptions): PeageClient {
  return createPeageClientWithNative({
    ...options,
    native: NativePeageAttest ?? unlinkedNativeAttest,
    platform: ReactNativePlatform.OS === 'android' ? PLATFORM_PLAY_INTEGRITY : PLATFORM_APP_ATTEST,
  })
}
