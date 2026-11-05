import { concatBytes } from '@peage/protocol'
import { certificateDerWith } from '@peage/tests'
import {
  type BaseBlock,
  Constructed,
  Integer,
  ObjectIdentifier,
  OctetString,
  Primitive,
  Sequence,
} from 'asn1js'
import { describe, expect, it } from 'vitest'

import { getCertificateExtension } from '../certificates.ts'
import { ASN1_TAG_CLASS_CONTEXT, CERTIFICATE_EXTENSIONS_TAG } from '../constants.ts'

const OID = '1.3.6.1.4.1.11129.2.1.17'
const OTHER_OID = '2.5.29.19'
const VALUE = Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x2a)

/** Only the parts `getCertificateExtension` reads: a TBSCertificate holding these fields. */
function certificateWithTbsFields(fields: BaseBlock[]): Uint8Array {
  const tbsCertificate = new Sequence({ value: fields })
  return new Uint8Array(new Sequence({ value: [tbsCertificate] }).toBER())
}

function extensionsField(content: BaseBlock[]): Constructed {
  return new Constructed({
    idBlock: { tagClass: ASN1_TAG_CLASS_CONTEXT, tagNumber: CERTIFICATE_EXTENSIONS_TAG },
    value: content,
  })
}

function certificateWithExtension(fields: BaseBlock[]): Uint8Array {
  const extension = new Sequence({ value: fields })
  return certificateWithTbsFields([extensionsField([new Sequence({ value: [extension] })])])
}

const oid = new ObjectIdentifier({ value: OID })
const primitiveValue = new OctetString({ valueHex: VALUE })

describe('getCertificateExtension', () => {
  it.each([false, true])('returns the value of the extension, critical: %s', (critical) => {
    const certificate = certificateDerWith({
      extensions: [
        { id: OTHER_OID, value: Uint8Array.of(0x30, 0x00) },
        { id: OID, value: VALUE, critical },
      ],
    })
    expect(getCertificateExtension(certificate, OID)).toStrictEqual(VALUE)
  })

  it('finds the extensions after issuerUniqueID and subjectUniqueID', () => {
    const certificate = certificateDerWith({
      withUniqueIds: true,
      extensions: [{ id: OID, value: VALUE }],
    })
    expect(getCertificateExtension(certificate, OID)).toStrictEqual(VALUE)
  })

  it('returns undefined for a certificate without extensions', () => {
    expect(getCertificateExtension(certificateDerWith({}), OID)).toBeUndefined()
  })

  it('returns undefined when no extension has the OID', () => {
    const certificate = certificateDerWith({
      extensions: [{ id: OTHER_OID, value: Uint8Array.of(0x30, 0x00) }],
    })
    expect(getCertificateExtension(certificate, OID)).toBeUndefined()
  })

  it('refuses a certificate with the extension twice', () => {
    const certificate = certificateDerWith({
      extensions: [
        { id: OID, value: VALUE },
        { id: OID, value: Uint8Array.of(0x30, 0x00) },
      ],
    })
    expect(() => getCertificateExtension(certificate, OID)).toThrow(
      `Certificate has more than one ${OID} extension`,
    )
  })

  it('refuses bytes after the certificate', () => {
    const certificate = concatBytes(certificateDerWith({}), Uint8Array.of(0x00))
    expect(() => getCertificateExtension(certificate, OID)).toThrow(
      'Certificate is not a complete ASN.1 value',
    )
  })

  it('ignores a duplicate of another extension', () => {
    const otherValue = Uint8Array.of(0x30, 0x00)
    const certificate = certificateDerWith({
      extensions: [
        { id: OTHER_OID, value: otherValue },
        { id: OTHER_OID, value: otherValue },
        { id: OID, value: VALUE },
      ],
    })
    expect(getCertificateExtension(certificate, OID)).toStrictEqual(VALUE)
  })

  it('reads an extension built from raw DER as the helper-built ones', () => {
    expect(
      getCertificateExtension(certificateWithExtension([oid, primitiveValue]), OID),
    ).toStrictEqual(VALUE)
  })

  it.each([
    [
      'a segmented value',
      [
        oid,
        new OctetString({ isConstructed: true, value: [new OctetString({ valueHex: VALUE })] }),
      ],
      'Certificate extension value is not a primitive octet string',
    ],
    [
      'a critical flag that is not a boolean',
      [oid, new Integer({ value: 1 }), primitiveValue],
      'Certificate extension value is not a primitive octet string',
    ],
    [
      'an id that is not an object identifier',
      [new Integer({ value: 1 }), primitiveValue],
      'Certificate extension id is not an object identifier',
    ],
  ])('refuses an extension with %s', (_case, fields, message) => {
    expect(() => getCertificateExtension(certificateWithExtension(fields), OID)).toThrow(message)
  })

  it.each([
    ['holds two sequences', extensionsField([new Sequence(), new Sequence()])],
    [
      'is primitive',
      new Primitive({
        idBlock: { tagClass: ASN1_TAG_CLASS_CONTEXT, tagNumber: CERTIFICATE_EXTENSIONS_TAG },
        valueHex: VALUE,
      }),
    ],
  ])('refuses an extensions field that %s', (_case, field) => {
    expect(() => getCertificateExtension(certificateWithTbsFields([field]), OID)).toThrow(
      'Certificate extensions field is malformed',
    )
  })

  it('refuses a TBSCertificate that is not a sequence', () => {
    const certificate = new Uint8Array(new Sequence({ value: [new Integer({ value: 1 })] }).toBER())
    expect(() => getCertificateExtension(certificate, OID)).toThrow(
      'TBSCertificate is not a sequence',
    )
  })

  it('refuses DER that is not a certificate', () => {
    expect(() => getCertificateExtension(Uint8Array.of(0x02, 0x01, 0x2a), OID)).toThrow(
      'Certificate is not a sequence',
    )
  })
})
