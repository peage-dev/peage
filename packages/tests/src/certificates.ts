import { AsnConvert, OctetString } from '@peculiar/asn1-schema'
import {
  AlgorithmIdentifier,
  Certificate,
  Extension,
  Extensions,
  Name,
  SubjectPublicKeyInfo,
  TBSCertificate,
  Validity,
  Version,
} from '@peculiar/asn1-x509'
import { generateKeyPairSync } from 'node:crypto'

import type { CertificateDerParams } from './types.ts'

const ECDSA_WITH_SHA256 = '1.2.840.10045.4.3.2'

function extensionsOf(params: CertificateDerParams): Extensions | undefined {
  if (params.extensions === undefined) {
    return undefined
  }
  return new Extensions(
    params.extensions.map(
      (extension) =>
        new Extension({
          extnID: extension.id,
          critical: extension.critical ?? false,
          extnValue: new OctetString(extension.value),
        }),
    ),
  )
}

/** Certificate DER with the given extensions, for parsing tests; its signature is not valid. */
export function certificateDerWith(params: CertificateDerParams): Uint8Array {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const signatureAlgorithm = new AlgorithmIdentifier({ algorithm: ECDSA_WITH_SHA256 })
  const needsVersionField = params.extensions !== undefined || params.withUniqueIds === true
  const tbsCertificate = new TBSCertificate({
    version: needsVersionField ? Version.v3 : Version.v1,
    serialNumber: new Uint8Array([0x01]).buffer,
    signature: signatureAlgorithm,
    issuer: new Name([]),
    validity: new Validity({ notBefore: new Date(0), notAfter: new Date('2048-01-01') }),
    subject: new Name([]),
    subjectPublicKeyInfo: AsnConvert.parse(
      publicKey.export({ format: 'der', type: 'spki' }),
      SubjectPublicKeyInfo,
    ),
    issuerUniqueID: params.withUniqueIds ? new Uint8Array([0xaa]).buffer : undefined,
    subjectUniqueID: params.withUniqueIds ? new Uint8Array([0xbb]).buffer : undefined,
    extensions: extensionsOf(params),
  })
  const certificate = new Certificate({
    tbsCertificate,
    signatureAlgorithm,
    signatureValue: new Uint8Array(64).buffer,
  })
  return new Uint8Array(AsnConvert.serialize(certificate))
}
