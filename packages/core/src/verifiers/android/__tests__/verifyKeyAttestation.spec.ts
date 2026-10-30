import { fromBase64 } from '@peage/protocol'
import {
  type KeyAttestationChainParams,
  type KeyDescriptionParams,
  SecurityLevel,
  VerifiedBootState,
  createKeyAttestationRoot,
  expiredCopyOf,
  issueKeyAttestationChain,
} from '@peage/tests'
import { type X509Certificate, generateKeyPairSync } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { assertKeyIdMatches } from '../../asserters.ts'
import { sha256 } from '../../bytes.ts'
import { GOOGLE_KEY_ATTESTATION_ROOTS } from '../constants.ts'
import { decodeCertificateChain, verifyKeyAttestation } from '../verifyKeyAttestation.ts'
import { PIXEL_3A_KEY_ATTESTATION, PIXEL_9A_KEY_ATTESTATION } from './deviceFixtures.ts'

const CHALLENGE = 'issued-challenge'
/** `keytool -list -v` on the React Native template's debug.keystore, which built the fixtures' app. */
const DEBUG_SIGNING_CERTIFICATE_SHA256 =
  'fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c'
const PACKAGE_NAME = 'dev.peage.specs'
const EXPECTED = { challenge: CHALLENGE, packageName: PACKAGE_NAME }
const ATTESTED = { attestationChallenge: sha256(CHALLENGE), packageName: PACKAGE_NAME }
const root = createKeyAttestationRoot()
const serialNumberedRoot = createKeyAttestationRoot({ serialNumber: 'f92009e853b6b045' })

function decode(chain: string[]): X509Certificate[] {
  return decodeCertificateChain(chain.map(fromBase64))
}

type TestChainParams = Partial<Omit<KeyAttestationChainParams, 'publicKey' | 'keyDescription'>> & {
  keyDescription?: Partial<KeyDescriptionParams> | null
}

function testChain({
  keyDescription = {},
  ...chainParams
}: TestChainParams = {}): X509Certificate[] {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  return decode(
    issueKeyAttestationChain({
      root,
      publicKey,
      keyDescription: keyDescription && { ...ATTESTED, ...keyDescription },
      ...chainParams,
    }),
  )
}

describe.each([
  ['Pixel 3a (Android 12, RSA root)', PIXEL_3A_KEY_ATTESTATION],
  ['Pixel 9a (Android 17, P-384 root)', PIXEL_9A_KEY_ATTESTATION],
])('verifyKeyAttestation on a real %s chain', (_device, fixture) => {
  const certificates = decode(fixture.certificateChain)
  const expected = { challenge: fixture.challenge, packageName: fixture.packageName }

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(fixture.verifiedAt)
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it("verifies it against Google's roots and returns the device key", () => {
    const { leaf } = verifyKeyAttestation(certificates, expected, GOOGLE_KEY_ATTESTATION_ROOTS)
    expect(() => assertKeyIdMatches(leaf.publicKey, fixture.keyId)).not.toThrow()
  })

  it('names the debug signing certificate the example app was built with', () => {
    const { application } = verifyKeyAttestation(
      certificates,
      expected,
      GOOGLE_KEY_ATTESTATION_ROOTS,
    )
    expect(
      application.signatureDigests.map((digest) => Buffer.from(digest).toString('hex')),
    ).toStrictEqual([DEBUG_SIGNING_CERTIFICATE_SHA256])
  })

  it('rejects it for another challenge', () => {
    expect(() =>
      verifyKeyAttestation(
        certificates,
        { ...expected, challenge: 'other' },
        GOOGLE_KEY_ATTESTATION_ROOTS,
      ),
    ).toThrow(/challenge does not match/)
  })

  it('rejects it for another package', () => {
    expect(() =>
      verifyKeyAttestation(
        certificates,
        { ...expected, packageName: 'com.other' },
        GOOGLE_KEY_ATTESTATION_ROOTS,
      ),
    ).toThrow(/different package/)
  })

  it('rejects it when only a test root is trusted', () => {
    expect(() => verifyKeyAttestation(certificates, expected, [root.certificate])).toThrow(
      /does not end in a trusted root/,
    )
  })
})

describe('verifyKeyAttestation once certificates expire', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('still trusts a factory-provisioned chain, as Google advises', () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    // The Pixel 3a's intermediates expire on 2029-09-24.
    vi.setSystemTime(new Date('2030-01-01'))
    const fixture = PIXEL_3A_KEY_ATTESTATION
    const expected = { challenge: fixture.challenge, packageName: fixture.packageName }
    expect(() =>
      verifyKeyAttestation(
        decode(fixture.certificateChain),
        expected,
        GOOGLE_KEY_ATTESTATION_ROOTS,
      ),
    ).not.toThrow()
  })

  it('rejects a remotely provisioned chain', () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    // The Pixel 9a's attestation certificate expires on 2026-11-06.
    vi.setSystemTime(new Date('2026-12-01'))
    const fixture = PIXEL_9A_KEY_ATTESTATION
    const expected = { challenge: fixture.challenge, packageName: fixture.packageName }
    expect(() =>
      verifyKeyAttestation(
        decode(fixture.certificateChain),
        expected,
        GOOGLE_KEY_ATTESTATION_ROOTS,
      ),
    ).toThrow(/expired/)
  })
})

describe('verifyKeyAttestation', () => {
  it('accepts a hardware key generated for the challenge and package', () => {
    expect(() => verifyKeyAttestation(testChain(), EXPECTED, [root.certificate])).not.toThrow()
  })

  it('accepts a StrongBox key', () => {
    const chain = testChain({
      keyDescription: {
        attestationSecurityLevel: SecurityLevel.strongBox,
        keySecurityLevel: SecurityLevel.strongBox,
      },
    })
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).not.toThrow()
  })

  it.each([
    ['its first 16 bytes', sha256(CHALLENGE).slice(0, 16)],
    ['no bytes', new Uint8Array()],
  ])('rejects an attested challenge digest truncated to %s', (_length, attestationChallenge) => {
    const chain = testChain({ keyDescription: { attestationChallenge } })
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).toThrow(
      /challenge does not match/,
    )
  })

  it('rejects an attestation made in software', () => {
    const chain = testChain({
      keyDescription: { attestationSecurityLevel: SecurityLevel.software },
    })
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).toThrow(
      /^Key attestation was not made in secure hardware$/,
    )
  })

  it('rejects a software key', () => {
    const chain = testChain({ keyDescription: { keySecurityLevel: SecurityLevel.software } })
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).toThrow(
      /^Attested key is not in secure hardware$/,
    )
  })

  it('rejects an imported key', () => {
    const chain = testChain({ keyDescription: { origin: 2 } })
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).toThrow(
      /generated in secure hardware/,
    )
  })

  it('rejects a key imported in hardware even when the software list says it was generated', () => {
    const chain = testChain({ keyDescription: { origin: 2, softwareEnforcedClaimsGenuine: true } })
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).toThrow(
      /generated in secure hardware/,
    )
  })

  it('rejects a key whose origin only the software list states', () => {
    const chain = testChain({
      keyDescription: { hardwareOmitsOrigin: true, softwareEnforcedClaimsGenuine: true },
    })
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).toThrow(
      /generated in secure hardware/,
    )
  })

  it('rejects a device with an unlocked bootloader', () => {
    const chain = testChain({ keyDescription: { deviceLocked: false } })
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).toThrow(
      /locked bootloader with verified boot/,
    )
  })

  it('rejects a bootloader unlocked in hardware even when the software list says it is locked', () => {
    const chain = testChain({
      keyDescription: { deviceLocked: false, softwareEnforcedClaimsGenuine: true },
    })
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).toThrow(
      /locked bootloader with verified boot/,
    )
  })

  it('rejects a device whose root of trust only the software list states', () => {
    const chain = testChain({
      keyDescription: { hardwareOmitsRootOfTrust: true, softwareEnforcedClaimsGenuine: true },
    })
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).toThrow(
      /locked bootloader with verified boot/,
    )
  })

  it('rejects a device whose boot is not verified', () => {
    const chain = testChain({ keyDescription: { verifiedBootState: VerifiedBootState.selfSigned } })
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).toThrow(
      /locked bootloader with verified boot/,
    )
  })

  it('rejects a package name that only the hardware-enforced list states', () => {
    const chain = testChain({ keyDescription: { applicationIdInHardwareOnly: true } })
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).toThrow(
      /different package/,
    )
  })

  it('rejects a leaf without a key description', () => {
    const chain = testChain({ keyDescription: null })
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).toThrow(
      /no key description/,
    )
  })

  it('rejects a chain from an untrusted root', () => {
    const chain = testChain()
    expect(() => verifyKeyAttestation(chain, EXPECTED, GOOGLE_KEY_ATTESTATION_ROOTS)).toThrow(
      /does not end in a trusted root/,
    )
  })

  it('rejects an intermediate that the trusted root did not sign', () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const forged = issueKeyAttestationChain({
      root: createKeyAttestationRoot(),
      publicKey,
      keyDescription: ATTESTED,
    })
    const chain = [...decode(forged).slice(0, -1), root.certificate]
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).toThrow(
      /not signed by the next certificate/,
    )
  })
})

describe('verifyKeyAttestation chain rules', () => {
  it('trusts an expired factory-provisioned intermediate', () => {
    const chain = testChain({ intermediate: { factoryProvisioned: true, expired: true } })
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).not.toThrow()
  })

  it.each([
    ['a common name', root],
    ["a serial number, as Google's RSA root is", serialNumberedRoot],
  ])(
    'rejects an expired remotely provisioned intermediate under a root named by %s',
    (_rootName, chainRoot) => {
      const chain = testChain({ root: chainRoot, intermediate: { expired: true } })
      expect(() => verifyKeyAttestation(chain, EXPECTED, [chainRoot.certificate])).toThrow(
        /expired/,
      )
    },
  )

  it('rejects a root named by a serial number repeated to pass as a factory intermediate', () => {
    const chain = testChain({ root: serialNumberedRoot, intermediate: { expired: true } })
    expect(() =>
      verifyKeyAttestation([...chain, serialNumberedRoot.certificate], EXPECTED, [
        serialNumberedRoot.certificate,
      ]),
    ).toThrow(/repeats its root/)
  })

  it("rejects a leaf that carries the trusted root's key", () => {
    const chain = issueKeyAttestationChain({
      root,
      publicKey: root.certificate.publicKey,
      keyDescription: ATTESTED,
    })
    expect(() => verifyKeyAttestation(decode(chain), EXPECTED, [root.certificate])).toThrow(
      /repeats its root/,
    )
  })

  it('rejects an intermediate that is not valid yet', () => {
    const chain = testChain({ intermediate: { notYetValid: true } })
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).toThrow(/not valid yet/)
  })

  it("ignores the leaf's validity period, which the device sets", () => {
    const chain = testChain({ leafExpired: true })
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).not.toThrow()
  })

  it('rejects a leaf that names another issuer than the intermediate whose key signed it', () => {
    const chain = testChain({ leafNamesAnotherIssuer: true })
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).toThrow(
      /not signed by the next certificate/,
    )
  })

  it('rejects a key description above the leaf', () => {
    const chain = testChain({ intermediate: { withKeyDescription: true } })
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).toThrow(
      /key description above the leaf/,
    )
  })

  it("swaps the device's expired copy of the root for the trusted one", () => {
    const chain = [...testChain().slice(0, -1), expiredCopyOf(root)]
    expect(() => verifyKeyAttestation(chain, EXPECTED, [root.certificate])).not.toThrow()
  })

  it('rejects a lone root certificate', () => {
    expect(() => verifyKeyAttestation([root.certificate], EXPECTED, [root.certificate])).toThrow(
      /at least a leaf and an intermediate/,
    )
  })
})
