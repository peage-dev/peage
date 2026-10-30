import type { KeyObject } from 'node:crypto'

import type { AppAttestConfig, AttestationEnvironment } from '../types.ts'
import type { ResolvedPlayIntegrityConfig } from './android/types.ts'

export type AttestedKey = {
  publicKey: KeyObject
  appId: string
  environment: AttestationEnvironment
  attestationCertificateSerialNumbers?: string[]
}

export type AssertionInput = {
  publicKey: KeyObject
  method: string
  path: string
  body: Uint8Array
  assertion: Uint8Array
}

export type VerifierConfig = {
  appAttest: AppAttestConfig | undefined
  playIntegrity: ResolvedPlayIntegrityConfig | undefined
}
