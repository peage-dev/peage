import type { AttestationEnvironment } from '@peage/core'

import { PLATFORM_APP_ATTEST, PLATFORM_PLAY_INTEGRITY, type Platform } from '@peage/protocol'

export const KEY_RECORD_FORMAT_VERSION = 1

/** Stored by index: the order is part of the format. */
export const PLATFORMS: readonly Platform[] = [PLATFORM_APP_ATTEST, PLATFORM_PLAY_INTEGRITY]

/** Stored by index: the order is part of the format. */
export const ENVIRONMENTS: readonly AttestationEnvironment[] = ['production', 'development']

/** The DER that precedes the uncompressed point in every P-256 SPKI. */
export const P256_SPKI_HEADER: Uint8Array = Uint8Array.from(
  Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'),
)
