import type { KeyObject } from 'node:crypto'

import type { KeyAttestationTestRoot, PlayIntegrityTestKeys } from './types.ts'

import { sha256 } from './hashing.ts'
import { issueKeyAttestationChain } from './keyAttestation.ts'
import {
  encodePlayIntegrityToken,
  playIntegrityNonce,
  playIntegrityProof,
  playIntegrityVerdict,
} from './playIntegrity.ts'

type PlayIntegrityRegistrationParams = {
  challenge: string
  /** The public key the device attests. */
  deviceKey: KeyObject
  packageName: string
  keys: PlayIntegrityTestKeys
  keyAttestationRoot: KeyAttestationTestRoot
}

/** The `proof` a genuine Android device submits to register its key against the challenge. */
export function playIntegrityRegistrationProof(
  params: PlayIntegrityRegistrationParams,
): Uint8Array {
  const verdict = playIntegrityVerdict({
    packageName: params.packageName,
    nonce: playIntegrityNonce(params.challenge, params.deviceKey),
  })
  const certificateChain = issueKeyAttestationChain({
    root: params.keyAttestationRoot,
    publicKey: params.deviceKey,
    keyDescription: {
      attestationChallenge: sha256(params.challenge),
      packageName: params.packageName,
    },
  })
  const token = encodePlayIntegrityToken(verdict, params.keys)
  return playIntegrityProof(token, certificateChain)
}
