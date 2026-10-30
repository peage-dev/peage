import {
  PLATFORM_APP_ATTEST,
  PLATFORM_PLAY_INTEGRITY,
  type Platform,
  fromBase64,
  isPlatform,
  toBase64,
} from '@peage/protocol'

import type { AppAttestConfig, AttestedKeyRecord, IssuedChallenge, PeageConfig } from './types.ts'
import type { ResolvedPlayIntegrityConfig } from './verifiers/android/types.ts'
import type { VerifierConfig } from './verifiers/types.ts'

import { PeageError, rethrowAs } from './errors.ts'
import { isAttestationEnvironment } from './guards.ts'
import { assertNotRevoked } from './verifiers/android/asserters.ts'

export function assertSomePlatformConfigured(config: PeageConfig): void {
  if (!config.appAttest && !config.playIntegrity) {
    throw new Error('Péage needs appAttest, playIntegrity, or both configured')
  }
}

export function assertValidAppAttestConfig(config: AppAttestConfig): void {
  if (!/^[A-Z0-9]{10}\.[^.\s]+(\.[^.\s]+)*$/.test(config.appId)) {
    throw new Error('App Attest appId must be "<Team ID>.<bundle identifier>"')
  }
  if (config.environment !== undefined && !isAttestationEnvironment(config.environment)) {
    throw new Error("App Attest environment must be 'production' or 'development'")
  }
}

export function assertPlatformConfigured<T>(
  platformConfig: T | undefined,
  platform: Platform,
): asserts platformConfig is T {
  if (platformConfig === undefined) {
    throw new PeageError('PLATFORM_DISABLED', `Platform ${platform} is not configured`)
  }
}

/** Throws a REQUEST_MALFORMED `PeageError` for anything but a platform Péage supports. */
export function assertPlatform(value: unknown): asserts value is Platform {
  if (!isPlatform(value)) {
    throw new PeageError('REQUEST_MALFORMED', `Unknown platform ${String(value)}`)
  }
}

export function assertChallengeShape(challenge: string): void {
  if (!/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
    throw new PeageError('REQUEST_MALFORMED', 'Challenge is not 32 bytes of unpadded base64url')
  }
}

/** One spelling per key: padded standard base64 of 32 bytes, as Apple emits it. */
export function assertCanonicalKeyId(keyId: string): void {
  if (!/^[A-Za-z0-9+/]{43}=$/.test(keyId) || toBase64(fromBase64(keyId)) !== keyId) {
    throw new PeageError('REQUEST_MALFORMED', 'Key id is not canonical base64 of 32 bytes')
  }
}

export function assertChallengeOutstanding(
  challenge: IssuedChallenge | null,
): asserts challenge is IssuedChallenge {
  if (!challenge || challenge.expiresAt <= Date.now()) {
    throw new PeageError('CHALLENGE_UNKNOWN', 'Unknown, used or expired challenge')
  }
}

export function assertSamePlatform(existing: AttestedKeyRecord | null, platform: Platform): void {
  if (existing && existing.platform !== platform) {
    throw new PeageError('ATTESTATION_INVALID', 'Key is already registered for another platform')
  }
}

export function assertKeyRegistered(
  record: AttestedKeyRecord | null,
): asserts record is AttestedKeyRecord {
  if (!record) {
    throw new PeageError('KEY_UNKNOWN', 'Unknown keyId')
  }
}

function assertRegisteredBy(record: AttestedKeyRecord, appId: string): void {
  if (record.appId !== appId) {
    throw new PeageError('KEY_UNKNOWN', 'Key was registered by another app')
  }
}

async function assertKeyNotRevoked(
  record: AttestedKeyRecord,
  playIntegrity: ResolvedPlayIntegrityConfig,
): Promise<void> {
  const revokedSerialNumbers = await playIntegrity.revocationList.latest()
  const serialNumbers = record.attestationCertificateSerialNumbers ?? []
  if (revokedSerialNumbers) {
    rethrowAs('KEY_UNKNOWN', () => assertNotRevoked(serialNumbers, revokedSerialNumbers))
  }
}

export async function assertKeyUsable(
  record: AttestedKeyRecord,
  config: VerifierConfig,
): Promise<void> {
  switch (record.platform) {
    case PLATFORM_APP_ATTEST: {
      const { appAttest } = config
      assertPlatformConfigured(appAttest, record.platform)
      assertRegisteredBy(record, appAttest.appId)
      return
    }
    case PLATFORM_PLAY_INTEGRITY: {
      const { playIntegrity } = config
      assertPlatformConfigured(playIntegrity, record.platform)
      assertRegisteredBy(record, playIntegrity.packageName)
      await assertKeyNotRevoked(record, playIntegrity)
      return
    }
    default:
      throw new Error(`Stored key ${record.keyId} has an unknown platform`)
  }
}
