import { concatBytes } from '@peage/protocol'
import { encode } from 'cbor2'
import { createSign, type KeyObject } from 'node:crypto'

import type { RequestToSign } from './types.ts'

import { clientDataHashOf } from './canonicalRequest.ts'
import { sha256 } from './hashing.ts'

/** rpIdHash (32) + flags (1) + signCount (4). */
const AUTHENTICATOR_DATA_HEADER_LENGTH = 37

/** Flags a real iOS 27 device sets alongside the extensions map: AT | ED. */
const IOS_27_FLAGS = 0xc0

/** The CBOR extensions map iOS 27 appends to authenticatorData, as captured on a real device. */
export const IOS_27_AUTHENTICATOR_EXTENSIONS: Uint8Array = new Uint8Array(
  encode({
    apple_bundle_version_01: '1',
    apple_validation_category_01: Uint8Array.of(3, 0, 0, 0),
  }),
)

type AuthenticatorDataOptions = {
  extensions?: Uint8Array
  /** Defaults to AT | ED when `extensions` is set (what iOS 27 sends), else 0. */
  flags?: number
}

type SignedAssertion = {
  authenticatorData: Uint8Array
  signature: Uint8Array
  /** CBOR `{ authenticatorData, signature }`, the blob `generateAssertion` returns. */
  assertion: Uint8Array
}

function appAttestAuthenticatorData(
  appId: string,
  options: AuthenticatorDataOptions = {},
): Uint8Array {
  const extensions = options.extensions ?? new Uint8Array()
  const header = new Uint8Array(AUTHENTICATOR_DATA_HEADER_LENGTH)
  header.set(sha256(new TextEncoder().encode(appId)), 0)
  header[32] = options.flags ?? (extensions.length > 0 ? IOS_27_FLAGS : 0)
  return concatBytes(header, extensions)
}

/** Signs as Apple's `generateAssertion` does. */
export function signAppAttestClientDataHash(
  params: {
    privateKey: KeyObject
    appId: string
    clientDataHash: Uint8Array
  } & AuthenticatorDataOptions,
): SignedAssertion {
  const authenticatorData = appAttestAuthenticatorData(params.appId, {
    extensions: params.extensions,
    flags: params.flags,
  })
  const nonce = sha256(concatBytes(authenticatorData, params.clientDataHash))
  const signature = new Uint8Array(createSign('sha256').update(nonce).sign(params.privateKey))
  const assertion = new Uint8Array(encode({ authenticatorData, signature }))
  return { authenticatorData, signature, assertion }
}

/** Signs a request as a Péage iOS client does. */
export function signAppAttestRequest(
  params: { privateKey: KeyObject; appId: string } & RequestToSign & AuthenticatorDataOptions,
): SignedAssertion {
  return signAppAttestClientDataHash({
    privateKey: params.privateKey,
    appId: params.appId,
    clientDataHash: clientDataHashOf(params),
    extensions: params.extensions,
    flags: params.flags,
  })
}
