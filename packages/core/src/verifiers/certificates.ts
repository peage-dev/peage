import type { X509Certificate } from 'node:crypto'

import { AsnConvert } from '@peculiar/asn1-schema'
import { Certificate } from '@peculiar/asn1-x509'

import { assertIssuedBy } from './asserters.ts'

/** Leaf first, trusted root last. */
export function verifyCertificateSignatures(certificates: X509Certificate[]): X509Certificate {
  const [leaf, ...issuers] = certificates
  if (leaf === undefined || issuers.length === 0) {
    throw new Error(
      'Certificate chain must contain at least a leaf and an intermediate certificate',
    )
  }
  if (leaf.ca) {
    throw new Error('Leaf certificate must not be a CA')
  }

  let certificate = leaf
  for (const issuer of issuers) {
    assertIssuedBy(certificate, issuer)
    certificate = issuer
  }
  return leaf
}

export function getCertificateExtension(
  certificateDer: Uint8Array,
  oid: string,
): Uint8Array | undefined {
  const { tbsCertificate } = AsnConvert.parse(certificateDer, Certificate)
  const extension = tbsCertificate.extensions?.find((entry) => entry.extnID === oid)
  return extension ? new Uint8Array(extension.extnValue.buffer) : undefined
}
