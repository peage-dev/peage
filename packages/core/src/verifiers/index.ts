import { PLATFORM_APP_ATTEST, PLATFORM_PLAY_INTEGRITY } from '@peage/protocol'

import type { AttestedKeyRecord, RegistrationRequest } from '../types.ts'
import type { AssertionInput, AttestedKey, VerifierConfig } from './types.ts'

import { assertPlatformConfigured } from '../asserters.ts'
import { rethrowAs } from '../errors.ts'
import { verifyPlayIntegrityAssertion } from './android/verifyPlayIntegrityAssertion.ts'
import { verifyPlayIntegrityAttestation } from './android/verifyPlayIntegrityAttestation.ts'
import { verifyAppAttestAssertion } from './ios/verifyAppAttestAssertion.ts'
import { verifyAppAttestAttestation } from './ios/verifyAppAttestAttestation.ts'

export async function verifyPlatformAttestation(
  request: RegistrationRequest,
  config: VerifierConfig,
): Promise<AttestedKey> {
  switch (request.platform) {
    case PLATFORM_APP_ATTEST: {
      const { appAttest } = config
      assertPlatformConfigured(appAttest, request.platform)
      const publicKey = rethrowAs('ATTESTATION_INVALID', () =>
        verifyAppAttestAttestation(request, appAttest),
      )
      return {
        publicKey,
        appId: appAttest.appId,
        environment: appAttest.environment ?? 'production',
      }
    }
    case PLATFORM_PLAY_INTEGRITY: {
      const { playIntegrity } = config
      assertPlatformConfigured(playIntegrity, request.platform)
      const revokedSerialNumbers = await playIntegrity.revocationList.load()
      return rethrowAs('ATTESTATION_INVALID', () =>
        verifyPlayIntegrityAttestation(request, playIntegrity, revokedSerialNumbers),
      )
    }
    default:
      throw new Error('Unsupported platform')
  }
}

export function verifyPlatformAssertion(
  record: AttestedKeyRecord,
  input: AssertionInput,
  config: VerifierConfig,
): void {
  switch (record.platform) {
    case PLATFORM_APP_ATTEST: {
      const { appAttest } = config
      assertPlatformConfigured(appAttest, record.platform)
      return rethrowAs('SIGNATURE_INVALID', () => verifyAppAttestAssertion(input, appAttest))
    }
    case PLATFORM_PLAY_INTEGRITY:
      return rethrowAs('SIGNATURE_INVALID', () => verifyPlayIntegrityAssertion(input))
    default:
      throw new Error('Unsupported platform')
  }
}
