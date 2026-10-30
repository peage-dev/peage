import { PLATFORM_APP_ATTEST, concatBytes, toBase64 } from '@peage/protocol'
import { IOS_27_AUTHENTICATOR_EXTENSIONS } from '@peage/tests'
import { Tag, encode } from 'cbor2'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { sha256 } from '../../bytes.ts'
import {
  APP_ATTEST_AAGUID_DEVELOPMENT,
  APP_ATTEST_AAGUID_PRODUCTION,
  APP_ATTEST_CREDENTIAL_DATA_FLAG,
  APP_ATTEST_CREDENTIAL_OFFSET,
  APP_ATTEST_PROOF_MAX_BYTES,
  APP_ATTEST_PROOF_MIN_BYTES,
} from '../constants.ts'
import {
  decodeAttestation,
  getAppAttestExpectedNonce,
  parseNonceExtension,
  verifyAppAttestAttestation,
  verifyAuthData,
  verifyCertificateChain,
  verifyChallenge,
} from '../verifyAppAttestAttestation.ts'
import { encodeCborMap, encodeCborMapOfEncodedEntries, encodeLongFormTextString } from './cbor.ts'
import {
  NONCE_AUTH_DATA,
  NONCE_CHALLENGE,
  NONCE_LEAF,
  ROGUE_LEAF,
  TEST_CHAIN,
  UNRELATED_ROOT,
} from './certificateFixtures.ts'
import { IOS_27_ATTESTATION, IOS_27_DEVICE } from './deviceFixtures.ts'
import { generateDerNonce } from './nonceExtension.ts'

const PADDING = new Uint8Array(APP_ATTEST_PROOF_MIN_BYTES).fill(7)
const MOCK_CERT = new Uint8Array([1, 2, 3])
const MOCK_AUTH_DATA = new Uint8Array([10, 11, 12])

function encodeProof(fields: Record<string, unknown>): Uint8Array {
  return encode({ padding: PADDING, ...fields })
}

describe('decodeAttestation', () => {
  it('decodes a well-formed App Attest object', () => {
    const proof = encodeProof({
      attStmt: { x5c: [MOCK_CERT, MOCK_CERT] },
      authData: MOCK_AUTH_DATA,
      fmt: 'apple-appattest',
    })
    expect(decodeAttestation(proof)).toStrictEqual({
      attStmt: { x5c: [MOCK_CERT, MOCK_CERT] },
      authData: MOCK_AUTH_DATA,
      fmt: 'apple-appattest',
    })
  })

  it('throws when the proof is shorter than the minimum length', () => {
    const tooShort = new Uint8Array(APP_ATTEST_PROOF_MIN_BYTES - 1)
    expect(() => decodeAttestation(tooShort)).toThrow(/outside the expected byte range/)
  })

  it('throws when the proof is longer than the maximum length', () => {
    const tooLong = new Uint8Array(APP_ATTEST_PROOF_MAX_BYTES + 1)
    expect(() => decodeAttestation(tooLong)).toThrow(/outside the expected byte range/)
  })

  it('throws when the proof is not valid CBOR', () => {
    // A run of 0xff bytes is a lone CBOR "break", invalid as a data item.
    expect(() => decodeAttestation(new Uint8Array(2048).fill(0xff))).toThrow()
  })

  it('throws when the decoded value is not a map', () => {
    expect(() => decodeAttestation(encode('x'.repeat(2048)))).toThrow(/not a CBOR map/)
  })

  it('throws when the map has an integer key', () => {
    const proof = encodeCborMapOfEncodedEntries([
      [encode('padding'), encode(PADDING)],
      [encode('fmt'), encode('apple-appattest')],
      [encode('attStmt'), encode({ x5c: [MOCK_CERT, MOCK_CERT] })],
      [encode('authData'), encode(MOCK_AUTH_DATA)],
      [encode(1), encode(0)],
    ])
    expect(() => decodeAttestation(proof)).toThrow(
      /^App Attest proof is not a CBOR map with text keys$/,
    )
  })

  it('throws when the map is wrapped in the self-described CBOR tag', () => {
    const fields = {
      padding: PADDING,
      fmt: 'apple-appattest',
      attStmt: { x5c: [MOCK_CERT, MOCK_CERT] },
      authData: MOCK_AUTH_DATA,
    }
    expect(() => decodeAttestation(encode(new Tag(55799, fields)))).toThrow(
      /^App Attest proof is not a CBOR map with text keys$/,
    )
  })

  it('throws when another data item follows the map', () => {
    const proof = encodeProof({
      attStmt: { x5c: [MOCK_CERT, MOCK_CERT] },
      authData: MOCK_AUTH_DATA,
      fmt: 'apple-appattest',
    })
    expect(() => decodeAttestation(concatBytes(proof, encode(0)))).toThrow(/^Extra data in input$/)
  })

  it('throws on an unexpected fmt', () => {
    const proof = encodeProof({
      attStmt: { x5c: [MOCK_CERT, MOCK_CERT] },
      authData: MOCK_AUTH_DATA,
      fmt: 'android-key',
    })
    expect(() => decodeAttestation(proof)).toThrow(/fmt is not apple-appattest/)
  })

  it('throws when attStmt is missing', () => {
    const proof = encodeProof({ authData: MOCK_AUTH_DATA, fmt: 'apple-appattest' })
    expect(() => decodeAttestation(proof)).toThrow(
      /^App Attest proof attStmt is not a CBOR map with text keys$/,
    )
  })

  it('throws when attStmt has an integer key', () => {
    const attStmt = encodeCborMapOfEncodedEntries([
      [encode('x5c'), encode([MOCK_CERT, MOCK_CERT])],
      [encode(1), encode(0)],
    ])
    const proof = encodeCborMap([
      ['padding', encode(PADDING)],
      ['fmt', encode('apple-appattest')],
      ['attStmt', attStmt],
      ['authData', encode(MOCK_AUTH_DATA)],
    ])
    expect(() => decodeAttestation(proof)).toThrow(
      /^App Attest proof attStmt is not a CBOR map with text keys$/,
    )
  })

  it('throws when x5c does not hold exactly two certificates', () => {
    const proof = encodeProof({
      attStmt: { x5c: [MOCK_CERT] },
      authData: MOCK_AUTH_DATA,
      fmt: 'apple-appattest',
    })
    expect(() => decodeAttestation(proof)).toThrow(/x5c must hold/)
  })

  it('throws when x5c contains non-byte entries', () => {
    const proof = encodeProof({
      attStmt: { x5c: ['not-bytes', 'not-bytes'] },
      authData: MOCK_AUTH_DATA,
      fmt: 'apple-appattest',
    })
    expect(() => decodeAttestation(proof)).toThrow(/x5c must hold/)
  })

  it('throws when authData is missing', () => {
    const proof = encodeProof({
      attStmt: { x5c: [MOCK_CERT, MOCK_CERT] },
      fmt: 'apple-appattest',
    })
    expect(() => decodeAttestation(proof)).toThrow(/authData is missing/)
  })
})

describe('verifyAppAttestAttestation', () => {
  it('rejects a structurally valid proof whose certificates are not certificates', () => {
    const proof = encodeProof({
      attStmt: { x5c: [MOCK_CERT, MOCK_CERT] },
      authData: MOCK_AUTH_DATA,
      fmt: 'apple-appattest',
    })
    const request = {
      challenge: 'challenge',
      keyId: toBase64(new Uint8Array(32)),
      platform: PLATFORM_APP_ATTEST,
      proof,
    }
    expect(() => verifyAppAttestAttestation(request, { appId: 'ABCDE12345.dev.peage' })).toThrow(
      expect.objectContaining({ code: 'ERR_OSSL_PEM_NO_START_LINE' }),
    )
  })
})

describe('real iOS 27 device attestation', () => {
  const request = {
    challenge: IOS_27_ATTESTATION.challenge,
    keyId: IOS_27_DEVICE.keyId,
    platform: PLATFORM_APP_ATTEST,
    proof: IOS_27_ATTESTATION.proof,
  }
  const config = { appId: IOS_27_DEVICE.appId, environment: 'development' as const }

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(IOS_27_ATTESTATION.verifiedAt)
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it("verifies Apple's chain, the nonce and authData, and returns the device key", () => {
    const publicKey = verifyAppAttestAttestation(request, config)
    expect(publicKey.equals(IOS_27_DEVICE.publicKey)).toBe(true)
  })

  it('rejects it for another challenge', () => {
    expect(() => verifyAppAttestAttestation({ ...request, challenge: 'other' }, config)).toThrow(
      /does not bind the issued challenge/,
    )
  })

  it('rejects it for another keyId', () => {
    const keyId = toBase64(new Uint8Array(32))
    expect(() => verifyAppAttestAttestation({ ...request, keyId }, config)).toThrow(
      /Key id does not match/,
    )
  })

  it('rejects a development attestation in production', () => {
    expect(() =>
      verifyAppAttestAttestation(request, { ...config, environment: 'production' }),
    ).toThrow(/unexpected environment AAGUID/)
  })

  it('rejects it for another App ID', () => {
    expect(() =>
      verifyAppAttestAttestation(request, { ...config, appId: 'ABCDE12345.dev.other.app' }),
    ).toThrow(/rpIdHash/)
  })

  it('rejects it re-encoded with a duplicate fmt key', () => {
    const { attStmt, authData } = decodeAttestation(IOS_27_ATTESTATION.proof)
    const proof = encodeCborMap([
      ['fmt', encode('none')],
      ['fmt', encode('apple-appattest')],
      ['attStmt', encode(attStmt)],
      ['authData', encode(authData)],
    ])
    expect(() => verifyAppAttestAttestation({ ...request, proof }, config)).toThrow(
      /^Duplicate key: /,
    )
  })

  it('rejects it re-encoded with a long-form duplicate fmt key before the short one', () => {
    const { attStmt, authData } = decodeAttestation(IOS_27_ATTESTATION.proof)
    const proof = encodeCborMapOfEncodedEntries([
      [encodeLongFormTextString('fmt'), encode('none')],
      [encode('fmt'), encode('apple-appattest')],
      [encode('attStmt'), encode(attStmt)],
      [encode('authData'), encode(authData)],
    ])
    expect(() => verifyAppAttestAttestation({ ...request, proof }, config)).toThrow(
      /^Unexpectedly long integer encoding /,
    )
  })

  it("rejects it with certificates that do not chain to Apple's root", () => {
    const attestation = decodeAttestation(IOS_27_ATTESTATION.proof)
    const proof = encodeProof({
      ...attestation,
      attStmt: { x5c: [new Uint8Array(TEST_CHAIN[0].raw), new Uint8Array(TEST_CHAIN[1].raw)] },
    })
    expect(() => verifyAppAttestAttestation({ ...request, proof }, config)).toThrow(
      /not signed by the next certificate/,
    )
  })
})

describe('verifyCertificateChain', () => {
  const [leaf, intermediate, root] = TEST_CHAIN

  it('returns the leaf certificate for a chain that links to the trusted root', () => {
    expect(verifyCertificateChain(TEST_CHAIN)).toBe(leaf)
  })

  it('rejects a chain with only one certificate', () => {
    expect(() => verifyCertificateChain([root])).toThrow(/at least a leaf and an intermediate/)
  })

  it('rejects a chain checked against an unrelated root', () => {
    expect(() => verifyCertificateChain([leaf, intermediate, UNRELATED_ROOT])).toThrow(
      /not signed by the next certificate/,
    )
  })

  it('rejects a truncated chain whose leaf no longer reaches the trusted root', () => {
    expect(() => verifyCertificateChain([leaf, root])).toThrow(/not signed by the next certificate/)
  })

  it('rejects a certificate issued by a leaf, which is not a CA', () => {
    expect(() => verifyCertificateChain([ROGUE_LEAF, leaf, intermediate, root])).toThrow(/not a CA/)
  })

  it('rejects a chain whose leaf is a CA', () => {
    expect(() => verifyCertificateChain([intermediate, root])).toThrow(/must not be a CA/)
  })

  // Every TEST_CHAIN certificate is valid from 2026-10-27T10:19:21Z to 2126-10-03T10:19:21Z.
  describe('validity period', () => {
    afterEach(() => {
      vi.useRealTimers()
    })

    it('rejects a chain once its certificates have expired', () => {
      vi.useFakeTimers({ now: new Date('2126-10-03T10:19:22Z') })
      expect(() => verifyCertificateChain(TEST_CHAIN)).toThrow(/expired/)
    })

    it('rejects a certificate more than five minutes before it becomes valid', () => {
      vi.useFakeTimers({ now: new Date('2026-10-27T10:13:00Z') })
      expect(() => verifyCertificateChain(TEST_CHAIN)).toThrow(/not valid yet/)
    })

    it('accepts a certificate issued moments ahead of the server clock', () => {
      vi.useFakeTimers({ now: new Date('2026-10-27T10:16:00Z') })
      expect(verifyCertificateChain(TEST_CHAIN)).toBe(leaf)
    })
  })
})

describe('parseNonceExtension', () => {
  const nonce = new Uint8Array(32).fill(9)

  it('extracts the nonce from a well-formed extension value', () => {
    expect(parseNonceExtension(generateDerNonce(nonce))).toEqual(nonce)
  })

  it('throws on an unexpected DER structure', () => {
    const wrapped = generateDerNonce(nonce)
    wrapped[0] = 0x31
    expect(() => parseNonceExtension(wrapped)).toThrow(/unexpected structure/)
  })

  it('throws when the nonce is truncated', () => {
    const wrapped = generateDerNonce(nonce)
    expect(() => parseNonceExtension(wrapped.slice(0, 20))).toThrow(/unexpected length/)
  })
})

describe('verifyChallenge', () => {
  it('accepts a credential cert whose nonce binds the challenge', () => {
    expect(() => verifyChallenge(NONCE_LEAF, NONCE_AUTH_DATA, NONCE_CHALLENGE)).not.toThrow()
  })

  it('rejects when the nonce binds a different challenge', () => {
    expect(() => verifyChallenge(NONCE_LEAF, NONCE_AUTH_DATA, 'other')).toThrow(
      /does not bind the issued challenge/,
    )
  })

  it('rejects when the credential cert has no nonce extension', () => {
    expect(() => verifyChallenge(TEST_CHAIN[0], NONCE_AUTH_DATA, NONCE_CHALLENGE)).toThrow(
      /missing the nonce extension/,
    )
  })
})

const APP_ID = 'ABCDE12345.dev.peage.specs'
const KEY_ID_BYTES = new Uint8Array(32).fill(5)
// Stand-in for the 77-byte COSE credentialPublicKey; the verifier never parses it.
const MOCK_CREDENTIAL_PUBLIC_KEY = new Uint8Array(77).fill(0xa5)
const IOS_27_TRAILING = concatBytes(MOCK_CREDENTIAL_PUBLIC_KEY, IOS_27_AUTHENTICATOR_EXTENSIONS)

function buildAuthData(
  overrides: {
    appId?: string
    credentialId?: Uint8Array
    aaguid?: Uint8Array
    flags?: number
    signCount?: number
    /** Bytes after the credentialId: credentialPublicKey, then any extensions. */
    trailing?: Uint8Array
  } = {},
): Uint8Array {
  const credentialId = overrides.credentialId ?? KEY_ID_BYTES
  const header = new Uint8Array(APP_ATTEST_CREDENTIAL_OFFSET)
  const view = new DataView(header.buffer)

  header.set(sha256(overrides.appId ?? APP_ID), 0)
  header[32] = overrides.flags ?? APP_ATTEST_CREDENTIAL_DATA_FLAG
  view.setUint32(33, overrides.signCount ?? 0)
  header.set(overrides.aaguid ?? APP_ATTEST_AAGUID_PRODUCTION, 37)
  view.setUint16(53, credentialId.length)

  return concatBytes(header, credentialId, overrides.trailing ?? new Uint8Array())
}

describe('verifyAuthData', () => {
  const appId = APP_ID
  const keyId = toBase64(KEY_ID_BYTES)

  it('accepts production authData bound to the App ID and key id', () => {
    expect(() => verifyAuthData(buildAuthData(), keyId, { appId })).not.toThrow()
  })

  it('accepts development authData when the development environment is set', () => {
    const authData = buildAuthData({ aaguid: APP_ATTEST_AAGUID_DEVELOPMENT })
    expect(() =>
      verifyAuthData(authData, keyId, { appId, environment: 'development' }),
    ).not.toThrow()
  })

  it('rejects development authData in production', () => {
    const authData = buildAuthData({ aaguid: APP_ATTEST_AAGUID_DEVELOPMENT })
    expect(() => verifyAuthData(authData, keyId, { appId })).toThrow(
      /unexpected environment AAGUID/,
    )
  })

  it('rejects production authData in development', () => {
    expect(() =>
      verifyAuthData(buildAuthData(), keyId, { appId, environment: 'development' }),
    ).toThrow(/unexpected environment AAGUID/)
  })

  it('rejects an rpIdHash bound to a different App ID', () => {
    const authData = buildAuthData({ appId: 'ZZZZZ99999.other.app' })
    expect(() => verifyAuthData(authData, keyId, { appId })).toThrow(/rpIdHash/)
  })

  it('rejects authData missing the attested-credential-data flag', () => {
    const authData = buildAuthData({ flags: 0x01 })
    expect(() => verifyAuthData(authData, keyId, { appId })).toThrow(
      /does not carry attested credential data/,
    )
  })

  it('rejects a non-zero signCount', () => {
    const authData = buildAuthData({ signCount: 1 })
    expect(() => verifyAuthData(authData, keyId, { appId })).toThrow(/signCount must be zero/)
  })

  it('rejects an unrecognized AAGUID', () => {
    const authData = buildAuthData({ aaguid: new Uint8Array(16).fill(0xab) })
    expect(() => verifyAuthData(authData, keyId, { appId, environment: 'development' })).toThrow(
      /unexpected environment AAGUID/,
    )
  })

  it('rejects a credentialId that does not match the client key id', () => {
    const authData = buildAuthData({ credentialId: new Uint8Array(32).fill(9) })
    expect(() => verifyAuthData(authData, keyId, { appId })).toThrow(
      /does not match the client key id/,
    )
  })

  it('rejects authData too short to contain attested credential data', () => {
    expect(() => verifyAuthData(new Uint8Array(40), keyId, { appId })).toThrow(/too short/)
  })

  it('rejects a credentialId longer than the authData', () => {
    const authData = buildAuthData().subarray(0, APP_ATTEST_CREDENTIAL_OFFSET + 10)
    expect(() => verifyAuthData(authData, keyId, { appId })).toThrow(/truncated/)
  })

  it('accepts iOS 27 authData with a credential key and trailing extensions', () => {
    const authData = buildAuthData({ flags: 0xc0, trailing: IOS_27_TRAILING })
    expect(() => verifyAuthData(authData, keyId, { appId })).not.toThrow()
  })
})

describe('getAppAttestExpectedNonce', () => {
  it('binds the trailing extensions, not just the parsed prefix', () => {
    const withExtensions = buildAuthData({ trailing: IOS_27_TRAILING })
    const withoutExtensions = withExtensions.subarray(
      0,
      withExtensions.length - IOS_27_AUTHENTICATOR_EXTENSIONS.length,
    )
    expect(getAppAttestExpectedNonce('challenge', withExtensions)).not.toStrictEqual(
      getAppAttestExpectedNonce('challenge', withoutExtensions),
    )
  })
})
