import { fromBase64 } from '@peage/protocol'
import { X509Certificate } from 'node:crypto'

import type { PlayIntegrityConfig } from '../../types.ts'
import type { ResolvedPlayIntegrityConfig } from './types.ts'

import { importSpkiPublicKey } from '../keys.ts'
import { assertValidDecryptionKey, assertValidVerificationKey } from './asserters.ts'
import { GOOGLE_KEY_ATTESTATION_ROOTS } from './constants.ts'
import { createGoogleRevocationList, createRevocationList } from './revocationList.ts'

export function resolvePlayIntegrityConfig(
  config: PlayIntegrityConfig,
): ResolvedPlayIntegrityConfig {
  const decryptionKey = fromBase64(config.decryptionKey)
  assertValidDecryptionKey(decryptionKey)

  const verificationKey = importSpkiPublicKey(config.verificationKey)
  assertValidVerificationKey(verificationKey)

  return {
    packageName: config.packageName,
    decryptionKey,
    verificationKey,
    allowUnrecognizedApps: config.allowUnrecognizedApps ?? false,
    keyAttestationRoots:
      config.keyAttestation?.trustedRoots?.map((pem) => new X509Certificate(pem)) ??
      GOOGLE_KEY_ATTESTATION_ROOTS,
    revocationList: createRevocationList(
      config.keyAttestation?.loadRevokedSerialNumbers ?? createGoogleRevocationList(),
    ),
  }
}
