import { type Platform, assertCanonicalRequest, toBase64 } from '@peage/protocol'

import type {
  AttestedKeyRecord,
  Peage,
  PeageConfig,
  PeageEvent,
  RegistrationRequest,
  SignedRequest,
  VerifiedRequest,
} from './types.ts'

import {
  assertCanonicalKeyId,
  assertChallengeShape,
  assertChallengeOutstanding,
  assertKeyRegistered,
  assertKeyUsable,
  assertPlatform,
  assertPlatformConfigured,
  assertSamePlatform,
} from './asserters.ts'
import { CHALLENGE_TTL_MS, getRandomChallenge } from './challenges.ts'
import { platformConfigOf, resolveVerifierConfig, warnAboutUnsafeSettings } from './config.ts'
import { PeageError, rethrowAs } from './errors.ts'
import { verifyPlatformAssertion, verifyPlatformAttestation } from './verifiers/index.ts'
import { importSpkiPublicKey } from './verifiers/keys.ts'

export { PeageError } from './errors.ts'
export type {
  AppAttestConfig,
  AttestationEnvironment,
  AttestedKeyRecord,
  IssuedChallenge,
  KeyAttestationConfig,
  LoadRevokedSerialNumbers,
  Peage,
  PeageConfig,
  PeageErrorCode,
  PeageEvent,
  PeageStore,
  PlayIntegrityConfig,
  RegistrationRequest,
  SignedRequest,
  VerifiedRequest,
} from './types.ts'
export type { Platform } from '@peage/protocol'

export { assertPlatform } from './asserters.ts'
export { isAttestationEnvironment } from './guards.ts'

/** Validates the config and returns the server core that adapters such as `@peage/express` wrap. */
export function createPeage(config: PeageConfig): Peage {
  const verifierConfig = resolveVerifierConfig(config)
  warnAboutUnsafeSettings(config)

  function emit(event: PeageEvent): void {
    try {
      const result: unknown = config.onEvent?.(event)
      if (result instanceof Promise) {
        result.catch(() => undefined)
      }
    } catch {}
  }

  function isPlatformEnabled(platform: Platform): boolean {
    return platformConfigOf(verifierConfig, platform) !== undefined
  }

  async function createChallenge(platform: Platform): Promise<string> {
    assertPlatform(platform)
    assertPlatformConfigured(platformConfigOf(verifierConfig, platform), platform)
    const value = getRandomChallenge()
    await config.store.saveChallenge({ value, platform, expiresAt: Date.now() + CHALLENGE_TTL_MS })
    return value
  }

  async function registerKey(request: RegistrationRequest): Promise<AttestedKeyRecord> {
    assertPlatform(request.platform)
    assertPlatformConfigured(platformConfigOf(verifierConfig, request.platform), request.platform)
    assertCanonicalKeyId(request.keyId)
    assertChallengeShape(request.challenge)

    const challenge = await config.store.takeChallenge({
      value: request.challenge,
      platform: request.platform,
    })
    assertChallengeOutstanding(challenge)

    const attested = await verifyPlatformAttestation(request, verifierConfig)

    const existing = await config.store.loadAttestedKey({ keyId: request.keyId })
    assertSamePlatform(existing, request.platform)

    const record: AttestedKeyRecord = {
      keyId: request.keyId,
      platform: request.platform,
      appId: attested.appId,
      environment: attested.environment,
      publicKey: toBase64(attested.publicKey.export({ format: 'der', type: 'spki' })),
      attestedAt: Date.now(),
      attestationCertificateSerialNumbers: attested.attestationCertificateSerialNumbers,
    }
    await config.store.saveAttestedKey(record)
    return record
  }

  async function solveChallenge(request: RegistrationRequest): Promise<AttestedKeyRecord> {
    try {
      const record = await registerKey(request)
      emit({ type: 'registration.accepted', keyId: record.keyId, platform: record.platform })
      return record
    } catch (error) {
      if (error instanceof PeageError) {
        emit({
          type: 'registration.rejected',
          keyId: request.keyId,
          platform: request.platform,
          error,
        })
      }
      throw error
    }
  }

  async function verifySignedRequest(request: SignedRequest): Promise<VerifiedRequest> {
    assertCanonicalKeyId(request.keyId)
    rethrowAs('REQUEST_MALFORMED', () => assertCanonicalRequest(request))

    const record = await config.store.loadAttestedKey({ keyId: request.keyId })
    assertKeyRegistered(record)
    await assertKeyUsable(record, verifierConfig)

    const publicKey = importSpkiPublicKey(record.publicKey)
    const body = await request.readBody()
    verifyPlatformAssertion(record, { ...request, publicKey, body }, verifierConfig)
    return { keyId: record.keyId, platform: record.platform, body }
  }

  async function verifyAssertion(request: SignedRequest): Promise<VerifiedRequest> {
    try {
      const verified = await verifySignedRequest(request)
      emit({ type: 'request.verified', keyId: verified.keyId, platform: verified.platform })
      return verified
    } catch (error) {
      if (error instanceof PeageError) {
        emit({ type: 'request.rejected', keyId: request.keyId, error })
      }
      throw error
    }
  }

  return {
    isPlatformEnabled,
    createChallenge,
    solveChallenge,
    verifyAssertion,
  }
}
