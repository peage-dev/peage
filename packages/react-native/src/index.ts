import { PLATFORM_APP_ATTEST, PLATFORM_PLAY_INTEGRITY } from '@peage/protocol'
import { Platform as ReactNativePlatform } from 'react-native'

import type { NativeAttest, PeageClient, PeageClientOptions } from './types.ts'

import { createPeageClientWithNative } from './client.ts'
import NativePeageAttest from './NativePeageAttest.ts'

export { PeageClientError } from './errors.ts'
export type { PeageClient, PeageClientErrorCode, PeageClientOptions } from './types.ts'

function linkedNativeModule(): NativeAttest {
  if (!NativePeageAttest) {
    throw new Error('Péage native module is not linked: rebuild the app (Expo Go is not supported)')
  }
  return NativePeageAttest
}

/**
 * The Péage client: App Attest on iOS, Play Integrity on Android. Throws if the native module
 * isn't linked, and a `TypeError` if `baseUrl` isn't an `http://` or `https://` URL whose path,
 * if any, starts with `/`.
 */
export function createPeageClient(options: PeageClientOptions): PeageClient {
  return createPeageClientWithNative({
    ...options,
    native: linkedNativeModule(),
    platform: ReactNativePlatform.OS === 'android' ? PLATFORM_PLAY_INTEGRITY : PLATFORM_APP_ATTEST,
  })
}
