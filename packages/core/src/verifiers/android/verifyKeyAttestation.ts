import { X509Certificate } from 'node:crypto'

import type { AttestationApplicationId, KeyDescription } from './types.ts'

import { assertNotExpired, assertValidityStarted } from '../asserters.ts'
import { bytesEqual, sha256 } from '../bytes.ts'
import { getCertificateExtension, verifyCertificateSignatures } from '../certificates.ts'
import { assertHardwareBacked, assertRootOnlyLast } from './asserters.ts'
import {
  KEY_ATTESTATION_MAX_CHAIN_LENGTH,
  KEY_DESCRIPTION_OID,
  KEY_ORIGIN_GENERATED,
  VERIFIED_BOOT_STATE_VERIFIED,
} from './constants.ts'
import { parseKeyDescription } from './keyDescription.ts'

type ExpectedKeyAttestation = {
  challenge: string
  packageName: string
}

/** Google's rule: only the leaf may carry a key description. */
function readKeyDescription(leaf: X509Certificate, issuers: X509Certificate[]): KeyDescription {
  if (issuers.some((issuer) => getCertificateExtension(issuer.raw, KEY_DESCRIPTION_OID))) {
    throw new Error('Key attestation chain has a key description above the leaf')
  }
  const extension = getCertificateExtension(leaf.raw, KEY_DESCRIPTION_OID)
  if (!extension) {
    throw new Error('Key attestation certificate has no key description')
  }
  return parseKeyDescription(extension)
}

function verifyKeyDescription(
  description: KeyDescription,
  expected: ExpectedKeyAttestation,
): AttestationApplicationId {
  assertHardwareBacked(
    description.attestationSecurityLevel,
    'Key attestation was not made in secure hardware',
  )
  assertHardwareBacked(description.keySecurityLevel, 'Attested key is not in secure hardware')

  if (!bytesEqual(description.attestationChallenge, sha256(expected.challenge))) {
    throw new Error('Key attestation challenge does not match the issued challenge')
  }

  const { origin, rootOfTrust } = description.hardwareEnforced
  if (origin !== KEY_ORIGIN_GENERATED) {
    throw new Error('Key attestation does not show the key was generated in secure hardware')
  }
  if (
    !rootOfTrust?.deviceLocked ||
    rootOfTrust.verifiedBootState !== VERIFIED_BOOT_STATE_VERIFIED
  ) {
    throw new Error('Key attestation does not show a locked bootloader with verified boot')
  }

  const applicationId = description.softwareEnforced.attestationApplicationId
  if (!applicationId?.packageNames.includes(expected.packageName)) {
    throw new Error('Key attestation names a different package')
  }
  return applicationId
}

/** Factory chains have a serial-numbered intermediate directly under the root. */
function isFactoryProvisioned(chain: X509Certificate[]): boolean {
  const intermediate = chain.at(-2)
  const attributes = intermediate?.subject.split('\n') ?? []
  return attributes.some((attribute) => attribute.startsWith('serialNumber='))
}

/**
 * Devices may send an expired re-issue of the root; the trusted copy with the
 * same key replaces it. The leaf's validity is set by the device and isn't
 * checked; expired factory certificates stay trusted, as Google advises.
 */
function verifyAgainstTrustedRoots(
  certificates: X509Certificate[],
  trustedRoots: X509Certificate[],
): { leaf: X509Certificate; chain: X509Certificate[] } {
  const deviceRoot = certificates.at(-1)
  const trustedRoot = trustedRoots.find((root) => deviceRoot?.publicKey.equals(root.publicKey))
  if (!trustedRoot) {
    throw new Error('Key attestation chain does not end in a trusted root')
  }

  const chain = [...certificates.slice(0, -1), trustedRoot]
  assertRootOnlyLast(chain, trustedRoot)
  const leaf = verifyCertificateSignatures(chain)
  const issuers = chain.slice(1)
  issuers.forEach(assertValidityStarted)
  if (!isFactoryProvisioned(chain)) {
    issuers.forEach(assertNotExpired)
  }
  return { leaf, chain }
}

export function decodeCertificateChain(chain: Uint8Array[]): X509Certificate[] {
  if (chain.length > KEY_ATTESTATION_MAX_CHAIN_LENGTH) {
    throw new Error('Key attestation chain has an unexpected length')
  }
  return chain.map((der) => new X509Certificate(der))
}

export function verifyKeyAttestation(
  certificates: X509Certificate[],
  expected: ExpectedKeyAttestation,
  trustedRoots: X509Certificate[],
): { leaf: X509Certificate; chain: X509Certificate[]; application: AttestationApplicationId } {
  const { leaf, chain } = verifyAgainstTrustedRoots(certificates, trustedRoots)
  const deviceIssuers = certificates.slice(1)
  const application = verifyKeyDescription(readKeyDescription(leaf, deviceIssuers), expected)
  return { leaf, chain, application }
}
