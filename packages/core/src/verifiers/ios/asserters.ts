import type { AttestationEnvironment } from '../../types.ts'
import type { AppAttestObject, AssertionEnvelope } from './types.ts'

import { bytesEqual, sha256 } from '../bytes.ts'
import { APP_ATTEST_AAGUID_DEVELOPMENT, APP_ATTEST_AAGUID_PRODUCTION } from './constants.ts'
import { isByteArray, isByteArrayList, isTextKeyedMap } from './guards.ts'

export function assertRpIdHash(rpIdHash: Uint8Array, appId: string): void {
  if (!bytesEqual(rpIdHash, sha256(appId))) {
    throw new Error('App Attest rpIdHash does not match the configured App ID')
  }
}

export function assertValidAssertionEnvelope(value: unknown): asserts value is AssertionEnvelope {
  if (!isTextKeyedMap(value)) {
    throw new Error('App Attest assertion is not a CBOR map with text keys')
  }
  if (!isByteArray(value.authenticatorData)) {
    throw new Error('App Attest assertion authenticatorData is not a byte string')
  }
  if (!isByteArray(value.signature)) {
    throw new Error('App Attest assertion signature is not a byte string')
  }
}

export function assertValidAppAttestObject(value: unknown): asserts value is AppAttestObject {
  if (!isTextKeyedMap(value)) {
    throw new Error('App Attest proof is not a CBOR map with text keys')
  }
  if (value.fmt !== 'apple-appattest') {
    throw new Error('App Attest proof fmt is not apple-appattest')
  }

  const { attStmt } = value
  if (!isTextKeyedMap(attStmt)) {
    throw new Error('App Attest proof attStmt is not a CBOR map with text keys')
  }

  const { x5c } = attStmt
  if (!isByteArrayList(x5c) || x5c.length !== 2) {
    throw new Error('App Attest proof x5c must hold the leaf and intermediate certificates')
  }

  if (!isByteArray(value.authData)) {
    throw new Error('App Attest proof authData is missing')
  }
}

export function assertExpectedAaguid(
  aaguid: Uint8Array,
  environment?: AttestationEnvironment,
): void {
  const expectedAaguid =
    environment === 'development' ? APP_ATTEST_AAGUID_DEVELOPMENT : APP_ATTEST_AAGUID_PRODUCTION
  if (!bytesEqual(aaguid, expectedAaguid)) {
    throw new Error('App Attest authData carries an unexpected environment AAGUID')
  }
}
