import { ASSERTION_BUCKET_SECONDS, assertionBucket, concatBytes } from '@peage/protocol'
import { IOS_27_AUTHENTICATOR_EXTENSIONS, flipLastByte, signAppAttestRequest } from '@peage/tests'
import { Tag, decode, encode } from 'cbor2'
import { generateKeyPairSync } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { AssertionInput } from '../../types.ts'

import { assertValidAssertionEnvelope } from '../asserters.ts'
import { verifyAppAttestAssertion } from '../verifyAppAttestAssertion.ts'
import {
  encodeCborMap,
  encodeCborMapOfEncodedEntries,
  encodeIndefiniteByteString,
  encodeLongFormTextString,
} from './cbor.ts'
import { IOS_27_ASSERTION, IOS_27_DEVICE } from './deviceFixtures.ts'

const APP_ID = 'ABCDE12345.dev.peage.specs'
const FROZEN_TIME = new Date('2026-05-01T12:00:00Z')
const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })

function encodeAssertion(authenticatorData: Uint8Array, signature: Uint8Array): Uint8Array {
  return new Uint8Array(encode({ authenticatorData, signature }))
}

function signedInput(
  overrides: {
    body?: string
    bucket?: number
    appIdInAuthData?: string
    extensions?: Uint8Array
    flags?: number
  } = {},
) {
  const request = {
    method: 'POST',
    path: '/api/protected',
    body: new TextEncoder().encode(overrides.body ?? '{"hello":"world"}'),
  }
  const { authenticatorData, signature } = signAppAttestRequest({
    ...request,
    appId: overrides.appIdInAuthData ?? APP_ID,
    bucket: overrides.bucket,
    extensions: overrides.extensions,
    flags: overrides.flags,
    privateKey,
  })
  const input: AssertionInput = {
    ...request,
    publicKey,
    assertion: encodeAssertion(authenticatorData, signature),
  }
  return { input, authenticatorData, signature }
}

function verify(input: AssertionInput) {
  return () => verifyAppAttestAssertion(input, { appId: APP_ID })
}

function currentBucket(): number {
  return assertionBucket(Math.floor(Date.now() / 1000))
}

describe('verifyAppAttestAssertion', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(FROZEN_TIME)
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('accepts an assertion signed in the current bucket', () => {
    expect(verify(signedInput().input)).not.toThrow()
  })

  it('accepts an assertion signed in the previous or next bucket', () => {
    const previous = signedInput({ bucket: currentBucket() - ASSERTION_BUCKET_SECONDS })
    const next = signedInput({ bucket: currentBucket() + ASSERTION_BUCKET_SECONDS })
    expect(verify(previous.input)).not.toThrow()
    expect(verify(next.input)).not.toThrow()
  })

  it('accepts an assertion over an empty request body', () => {
    expect(verify(signedInput({ body: '' }).input)).not.toThrow()
  })

  it('rejects an assertion signed two buckets in the past', () => {
    const stale = signedInput({ bucket: currentBucket() - 2 * ASSERTION_BUCKET_SECONDS })
    expect(verify(stale.input)).toThrow(/recent time bucket/)
  })

  it('rejects an assertion signed two buckets in the future', () => {
    const early = signedInput({ bucket: currentBucket() + 2 * ASSERTION_BUCKET_SECONDS })
    expect(verify(early.input)).toThrow(/recent time bucket/)
  })

  it('rejects an assertion whose rpIdHash binds a different App ID', () => {
    const { input } = signedInput({ appIdInAuthData: 'OTHER99999.app' })
    expect(verify(input)).toThrow(/rpIdHash/)
  })

  it('rejects a request whose method, path or body differs from what was signed', () => {
    const { input } = signedInput()
    expect(verify({ ...input, method: 'GET' })).toThrow(/recent time bucket/)
    expect(verify({ ...input, path: '/api/other' })).toThrow(/recent time bucket/)
    expect(verify({ ...input, body: new TextEncoder().encode('tampered') })).toThrow(
      /recent time bucket/,
    )
  })

  it('rejects a tampered signature', () => {
    const { input, authenticatorData, signature } = signedInput()
    const tampered = flipLastByte(signature)
    expect(verify({ ...input, assertion: encodeAssertion(authenticatorData, tampered) })).toThrow(
      /recent time bucket/,
    )
  })

  it('rejects authenticatorData shorter than the 37-byte header', () => {
    const { input, authenticatorData, signature } = signedInput()
    const truncated = encodeAssertion(authenticatorData.subarray(0, 36), signature)
    expect(verify({ ...input, assertion: truncated })).toThrow(/too short/)
  })

  it('accepts authenticatorData carrying iOS 27 trailing extensions', () => {
    const { input } = signedInput({ extensions: IOS_27_AUTHENTICATOR_EXTENSIONS })
    expect(verify(input)).not.toThrow()
  })

  it('accepts trailing extensions even when the ED flag is not set', () => {
    const { input } = signedInput({ extensions: IOS_27_AUTHENTICATOR_EXTENSIONS, flags: 0x40 })
    expect(verify(input)).not.toThrow()
  })

  it('rejects when signed trailing extensions are stripped', () => {
    const { input, authenticatorData, signature } = signedInput({
      extensions: IOS_27_AUTHENTICATOR_EXTENSIONS,
    })
    const stripped = encodeAssertion(authenticatorData.subarray(0, 37), signature)
    expect(verify({ ...input, assertion: stripped })).toThrow(/recent time bucket/)
  })

  it('rejects an assertion that is not a CBOR map', () => {
    const { input } = signedInput()
    expect(verify({ ...input, assertion: new Uint8Array(encode('text')) })).toThrow(
      /not a CBOR map/,
    )
  })

  it('rejects an assertion that is a CBOR array', () => {
    const { input, authenticatorData, signature } = signedInput()
    const assertion = new Uint8Array(encode([authenticatorData, signature]))
    expect(verify({ ...input, assertion })).toThrow(
      /^App Attest assertion is not a CBOR map with text keys$/,
    )
  })

  describe('real iOS 27 device assertion', () => {
    const { verifiedAt, ...signed } = IOS_27_ASSERTION
    const input = { ...signed, publicKey: IOS_27_DEVICE.publicKey }
    const config = { appId: IOS_27_DEVICE.appId }

    beforeEach(() => {
      vi.setSystemTime(verifiedAt)
    })

    it('verifies the tagged signature over the full 99-byte authenticatorData', () => {
      expect(() => verifyAppAttestAssertion(input, config)).not.toThrow()
    })

    it('rejects the same assertion against a different path', () => {
      expect(() => verifyAppAttestAssertion({ ...input, path: '/api/other' }, config)).toThrow(
        /recent time bucket/,
      )
    })

    describe('re-encoded', () => {
      const envelope = decode(IOS_27_ASSERTION.assertion)
      assertValidAssertionEnvelope(envelope)
      const { authenticatorData, signature } = envelope

      it('rejects it with a duplicate signature key', () => {
        const assertion = encodeCborMap([
          ['authenticatorData', encode(authenticatorData)],
          ['signature', encode(flipLastByte(signature))],
          ['signature', encode(signature)],
        ])
        expect(() => verifyAppAttestAssertion({ ...input, assertion }, config)).toThrow(
          /^Duplicate key: /,
        )
      })

      it('rejects it with a long-form duplicate signature key before the short one', () => {
        const assertion = encodeCborMapOfEncodedEntries([
          [encode('authenticatorData'), encode(authenticatorData)],
          [encodeLongFormTextString('signature'), encode(flipLastByte(signature))],
          [encode('signature'), encode(signature)],
        ])
        expect(() => verifyAppAttestAssertion({ ...input, assertion }, config)).toThrow(
          /^Unexpectedly long integer encoding /,
        )
      })

      it('rejects it with authenticatorData as a tag-64 byte string', () => {
        const assertion = encodeCborMap([
          ['authenticatorData', encode(new Tag(64, authenticatorData))],
          ['signature', encode(signature)],
        ])
        expect(() => verifyAppAttestAssertion({ ...input, assertion }, config)).toThrow(
          /^App Attest assertion authenticatorData is not a byte string$/,
        )
      })

      it('rejects it with an extra integer key', () => {
        const assertion = encodeCborMapOfEncodedEntries([
          [encode('authenticatorData'), encode(authenticatorData)],
          [encode('signature'), encode(signature)],
          [encode(1), encode(0)],
        ])
        expect(() => verifyAppAttestAssertion({ ...input, assertion }, config)).toThrow(
          /^App Attest assertion is not a CBOR map with text keys$/,
        )
      })

      it('rejects it as a map wrapped in the self-described CBOR tag', () => {
        const assertion = encode(new Tag(55799, { authenticatorData, signature }))
        expect(() => verifyAppAttestAssertion({ ...input, assertion }, config)).toThrow(
          /^App Attest assertion is not a CBOR map with text keys$/,
        )
      })

      it('rejects it followed by another data item', () => {
        const assertion = concatBytes(IOS_27_ASSERTION.assertion, encode(0))
        expect(() => verifyAppAttestAssertion({ ...input, assertion }, config)).toThrow(
          /^Extra data in input$/,
        )
      })

      it('rejects it with authenticatorData as an indefinite-length byte string', () => {
        const assertion = encodeCborMap([
          ['authenticatorData', encodeIndefiniteByteString(authenticatorData)],
          ['signature', encode(signature)],
        ])
        expect(() => verifyAppAttestAssertion({ ...input, assertion }, config)).toThrow(
          /^Streaming not supported$/,
        )
      })
    })
  })
})
