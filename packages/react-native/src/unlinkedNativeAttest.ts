import type { NativeAttest } from './types.ts'

import { PeageClientError } from './errors.ts'

async function rejectAsUnlinked(): Promise<never> {
  throw new PeageClientError(
    'UNSUPPORTED',
    'Péage native module is not linked: rebuild the app (Expo Go is not supported)',
  )
}

export const unlinkedNativeAttest: NativeAttest = {
  isSupported: async () => false,
  generateKey: rejectAsUnlinked,
  markAttested: rejectAsUnlinked,
  getKeyId: rejectAsUnlinked,
  clearKeyId: async () => {},
  attestKey: rejectAsUnlinked,
  generateAssertion: rejectAsUnlinked,
  sha256: rejectAsUnlinked,
}
