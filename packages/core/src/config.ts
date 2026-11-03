import { PLATFORM_APP_ATTEST, PLATFORM_PLAY_INTEGRITY, type Platform } from '@peage/protocol'

import type { AppAttestConfig, PeageConfig } from './types.ts'
import type { ResolvedPlayIntegrityConfig } from './verifiers/android/types.ts'
import type { VerifierConfig } from './verifiers/types.ts'

import {
  assertSomePlatformConfigured,
  assertValidAppAttestConfig,
  assertValidDebugToken,
  assertValidMaxKeyAgeSeconds,
} from './asserters.ts'
import { resolvePlayIntegrityConfig } from './verifiers/android/config.ts'

export const DEFAULT_MAX_KEY_AGE_SECONDS: number = 30 * 24 * 60 * 60

export function resolveMaxKeyAgeMs(config: PeageConfig): number {
  const maxKeyAgeSeconds = config.maxKeyAgeSeconds ?? DEFAULT_MAX_KEY_AGE_SECONDS
  assertValidMaxKeyAgeSeconds(maxKeyAgeSeconds)
  return maxKeyAgeSeconds * 1000
}

export function resolveVerifierConfig(config: PeageConfig): VerifierConfig {
  assertSomePlatformConfigured(config)
  if (config.appAttest) {
    assertValidAppAttestConfig(config.appAttest)
  }
  assertValidDebugToken(config)
  return {
    appAttest: config.appAttest,
    playIntegrity: config.playIntegrity && resolvePlayIntegrityConfig(config.playIntegrity),
  }
}

export function platformConfigOf(
  config: VerifierConfig,
  platform: Platform,
): AppAttestConfig | ResolvedPlayIntegrityConfig | undefined {
  switch (platform) {
    case PLATFORM_APP_ATTEST:
      return config.appAttest
    case PLATFORM_PLAY_INTEGRITY:
      return config.playIntegrity
    default:
      return undefined
  }
}

export function warnAboutUnsafeSettings(config: PeageConfig): void {
  if (config.appAttest?.environment === 'development') {
    console.warn('[peage] WARNING: App Attest accepts development attestations')
  }
  if (config.playIntegrity?.allowUnrecognizedApps) {
    console.warn('[peage] WARNING: Play Integrity accepts apps Play does not recognize')
  }
  if (config.playIntegrity?.keyAttestation?.trustedRoots) {
    console.warn("[peage] WARNING: Key attestation trusts the configured roots instead of Google's")
  }
  if (config.debugToken !== undefined) {
    console.warn('[peage] WARNING: Requests carrying the debug token skip attestation')
  }
}
