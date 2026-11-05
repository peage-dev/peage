import type { X509Certificate } from 'node:crypto'

import { type BaseBlock, Boolean as AsnBoolean, Constructed, ObjectIdentifier } from 'asn1js'

import { bytesOf, decodeAsn1, sequenceItems } from './asn1.ts'
import { assertAtMostOneExtension, assertIssuedBy } from './asserters.ts'
import { ASN1_TAG_CLASS_CONTEXT, CERTIFICATE_EXTENSIONS_TAG } from './constants.ts'

type CertificateExtension = { id: string; value: Uint8Array }

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

function isExtensionsField(block: BaseBlock): boolean {
  return (
    block.idBlock.tagClass === ASN1_TAG_CLASS_CONTEXT &&
    block.idBlock.tagNumber === CERTIFICATE_EXTENSIONS_TAG
  )
}

/** The extnValue, after an optional critical BOOLEAN. */
function extensionValueOf(fields: BaseBlock[]): BaseBlock | undefined {
  if (fields.length === 1) {
    return fields[0]
  }
  if (fields.length === 2 && fields[0] instanceof AsnBoolean) {
    return fields[1]
  }
  return undefined
}

/** Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING } */
function readExtension(block: BaseBlock): CertificateExtension {
  const [id, ...fields] = sequenceItems(block, 'Certificate extension')
  if (!(id instanceof ObjectIdentifier)) {
    throw new Error('Certificate extension id is not an object identifier')
  }
  const value = bytesOf(extensionValueOf(fields), 'Certificate extension value')
  return { id: id.valueBlock.toString(), value: value.slice() }
}

function extensionsOf(certificateDer: Uint8Array): CertificateExtension[] {
  const [tbsCertificate] = sequenceItems(decodeAsn1(certificateDer, 'Certificate'), 'Certificate')
  const extensionsField = sequenceItems(tbsCertificate, 'TBSCertificate').find(isExtensionsField)
  if (extensionsField === undefined) {
    return []
  }
  if (!(extensionsField instanceof Constructed) || extensionsField.valueBlock.value.length !== 1) {
    throw new Error('Certificate extensions field is malformed')
  }
  const [extensions] = extensionsField.valueBlock.value
  return sequenceItems(extensions, 'Certificate extensions').map(readExtension)
}

/** The value of the certificate's extension `oid`, or undefined when it has none. */
export function getCertificateExtension(
  certificateDer: Uint8Array,
  oid: string,
): Uint8Array | undefined {
  const matches = extensionsOf(certificateDer).filter((extension) => extension.id === oid)
  assertAtMostOneExtension(matches, oid)
  return matches[0]?.value
}
