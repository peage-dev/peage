import {
  AttestationApplicationId,
  AttestationPackageInfo,
  AuthorizationList,
  id_ce_keyDescription,
  IntegerSet,
  KeyDescription,
  RootOfTrust,
  SecurityLevel,
  VerifiedBootState,
} from '@peculiar/asn1-android'
import { AsnConvert, OctetString } from '@peculiar/asn1-schema'
import {
  AlgorithmIdentifier,
  AttributeTypeAndValue,
  AttributeValue,
  BasicConstraints,
  Certificate,
  Extension,
  Extensions,
  id_ce_basicConstraints,
  Name,
  RelativeDistinguishedName,
  SubjectPublicKeyInfo,
  TBSCertificate,
  Validity,
  Version,
} from '@peculiar/asn1-x509'
import {
  generateKeyPairSync,
  type KeyObject,
  randomBytes,
  sign,
  X509Certificate,
} from 'node:crypto'

import type {
  KeyAttestationChainParams,
  KeyAttestationTestRoot,
  KeyDescriptionParams,
} from './types.ts'

import { APP_SIGNING_CERTIFICATE_DIGEST } from './playIntegrity.ts'

const ECDSA_WITH_SHA256 = '1.2.840.10045.4.3.2'
const COMMON_NAME = '2.5.4.3'
const KEYMINT_VERSION = 300
const KEY_PURPOSE_SIGN = 2
const KEY_ALGORITHM_EC = 3
const EC_CURVE_P256 = 1
const KEY_ORIGIN_GENERATED = 0
const SERIAL_NUMBER = '2.5.4.5'
const ROOT_NAME = 'Péage Test Attestation Root'
const INTERMEDIATE_NAME = 'Péage Test Attestation Intermediate'
const OTHER_INTERMEDIATE_NAME = 'Péage Test Other Intermediate'
const FACTORY_INTERMEDIATE_SERIAL = 'f00df00df00df00d'
const EXPIRED = new Date('2020-01-01')
const NOT_EXPIRED = new Date('2048-01-01')
const NOT_YET_VALID = new Date('2040-01-01')

type CertificateRequest = {
  subject: Name
  publicKey: KeyObject
  issuer: { name: Name; privateKey: KeyObject }
  isAuthority: boolean
  notBefore?: Date
  notAfter?: Date
  /** DER INTEGER bytes; random and positive by default. */
  serialNumber?: Uint8Array
  extensions?: Extension[]
}

function nameOf(type: string, value: string): Name {
  const attribute = new AttributeTypeAndValue({
    type,
    value: new AttributeValue({ utf8String: value }),
  })
  return new Name([new RelativeDistinguishedName([attribute])])
}

function extensionOf(extnID: string, value: object): Extension {
  return new Extension({ extnID, extnValue: new OctetString(AsnConvert.serialize(value)) })
}

function issueCertificate(request: CertificateRequest): X509Certificate {
  const signatureAlgorithm = new AlgorithmIdentifier({ algorithm: ECDSA_WITH_SHA256 })
  const spki = request.publicKey.export({ format: 'der', type: 'spki' })
  const basicConstraints = extensionOf(
    id_ce_basicConstraints,
    new BasicConstraints({ cA: request.isAuthority }),
  )
  const tbsCertificate = new TBSCertificate({
    version: Version.v3,
    // A leading 0x01 byte keeps the DER serial positive and minimally encoded.
    serialNumber: (request.serialNumber ?? new Uint8Array([0x01, ...randomBytes(8)])).slice()
      .buffer,
    signature: signatureAlgorithm,
    issuer: request.issuer.name,
    validity: new Validity({
      notBefore: request.notBefore ?? new Date(0),
      notAfter: request.notAfter ?? NOT_EXPIRED,
    }),
    subject: request.subject,
    subjectPublicKeyInfo: AsnConvert.parse(spki, SubjectPublicKeyInfo),
    extensions: new Extensions([basicConstraints, ...(request.extensions ?? [])]),
  })
  const signature = sign('sha256', Buffer.from(AsnConvert.serialize(tbsCertificate)), {
    key: request.issuer.privateKey,
  })
  const certificate = new Certificate({
    tbsCertificate,
    signatureAlgorithm,
    signatureValue: new Uint8Array(signature).buffer,
  })
  return new X509Certificate(Buffer.from(AsnConvert.serialize(certificate)))
}

function rootNameOf(serialNumber: string | undefined): Name {
  return serialNumber === undefined
    ? nameOf(COMMON_NAME, ROOT_NAME)
    : nameOf(SERIAL_NUMBER, serialNumber)
}

/** `serialNumber` names the root by a serial number, as Google's RSA root is named. */
export function createKeyAttestationRoot(
  options: { serialNumber?: string } = {},
): KeyAttestationTestRoot {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const name = rootNameOf(options.serialNumber)
  const certificate = issueCertificate({
    subject: name,
    publicKey,
    issuer: { name, privateKey },
    isAuthority: true,
  })
  return { certificate, privateKey, name }
}

/** A self-signed certificate with the given DER serial number bytes, e.g. a negative one. */
export function certificateWithSerialNumber(serialNumber: Uint8Array): X509Certificate {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const name = nameOf(COMMON_NAME, ROOT_NAME)
  return issueCertificate({
    subject: name,
    publicKey,
    issuer: { name, privateKey },
    isAuthority: true,
    serialNumber,
  })
}

/** An expired certificate for the same root key, like the copy some devices send. */
export function expiredCopyOf(root: KeyAttestationTestRoot): X509Certificate {
  return issueCertificate({
    subject: root.name,
    publicKey: root.certificate.publicKey,
    issuer: { name: root.name, privateKey: root.privateKey },
    isAuthority: true,
    notAfter: EXPIRED,
  })
}

function rootOfTrustOf(deviceLocked: boolean, verifiedBootState: VerifiedBootState): RootOfTrust {
  return new RootOfTrust({
    verifiedBootKey: new OctetString(randomBytes(32)),
    deviceLocked,
    verifiedBootState,
    verifiedBootHash: new OctetString(randomBytes(32)),
  })
}

function softwareEnforcedOf(
  params: KeyDescriptionParams,
  attestationApplicationId: OctetString,
): AuthorizationList {
  const softwareEnforced = new AuthorizationList()
  if (params.softwareEnforcedClaimsGenuine) {
    softwareEnforced.origin = KEY_ORIGIN_GENERATED
    softwareEnforced.rootOfTrust = rootOfTrustOf(true, VerifiedBootState.verified)
  }
  if (!params.applicationIdInHardwareOnly) {
    softwareEnforced.attestationApplicationId = attestationApplicationId
  }
  return softwareEnforced
}

function hardwareEnforcedOf(
  params: KeyDescriptionParams,
  attestationApplicationId: OctetString,
): AuthorizationList {
  const hardwareEnforced = new AuthorizationList({
    purpose: new IntegerSet([KEY_PURPOSE_SIGN]),
    algorithm: KEY_ALGORITHM_EC,
    keySize: 256,
    ecCurve: EC_CURVE_P256,
  })
  if (params.applicationIdInHardwareOnly) {
    hardwareEnforced.attestationApplicationId = attestationApplicationId
  }
  if (!params.hardwareOmitsOrigin) {
    hardwareEnforced.origin = params.origin ?? KEY_ORIGIN_GENERATED
  }
  if (!params.hardwareOmitsRootOfTrust) {
    hardwareEnforced.rootOfTrust = rootOfTrustOf(
      params.deviceLocked ?? true,
      params.verifiedBootState ?? VerifiedBootState.verified,
    )
  }
  return hardwareEnforced
}

function keyDescriptionOf(params: KeyDescriptionParams): KeyDescription {
  const packageInfo = new AttestationPackageInfo({
    packageName: new OctetString(Buffer.from(params.packageName)),
    version: 1,
  })
  const applicationId = new AttestationApplicationId({
    packageInfos: [packageInfo],
    signatureDigests: (params.signingCertificateDigests ?? [APP_SIGNING_CERTIFICATE_DIGEST]).map(
      (digest) => new OctetString(digest),
    ),
  })
  const attestationApplicationId = new OctetString(AsnConvert.serialize(applicationId))
  return new KeyDescription({
    attestationVersion: KEYMINT_VERSION,
    attestationSecurityLevel: params.attestationSecurityLevel ?? SecurityLevel.trustedEnvironment,
    keymasterVersion: KEYMINT_VERSION,
    keymasterSecurityLevel: params.keySecurityLevel ?? SecurityLevel.trustedEnvironment,
    attestationChallenge: new OctetString(params.attestationChallenge),
    uniqueId: new OctetString(),
    softwareEnforced: softwareEnforcedOf(params, attestationApplicationId),
    teeEnforced: hardwareEnforcedOf(params, attestationApplicationId),
  })
}

/**
 * The chain a Keystore key's `getCertificateChain` returns, as base64 DER:
 * leaf, intermediate, root.
 */
export function issueKeyAttestationChain(params: KeyAttestationChainParams): string[] {
  const keyDescriptionExtensions = params.keyDescription
    ? [extensionOf(id_ce_keyDescription, keyDescriptionOf(params.keyDescription))]
    : []
  const intermediateKeys = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const intermediateName = params.intermediate?.factoryProvisioned
    ? nameOf(SERIAL_NUMBER, FACTORY_INTERMEDIATE_SERIAL)
    : nameOf(COMMON_NAME, INTERMEDIATE_NAME)
  const intermediate = issueCertificate({
    subject: intermediateName,
    publicKey: intermediateKeys.publicKey,
    issuer: { name: params.root.name, privateKey: params.root.privateKey },
    isAuthority: true,
    notBefore: params.intermediate?.notYetValid ? NOT_YET_VALID : undefined,
    notAfter: params.intermediate?.expired ? EXPIRED : NOT_EXPIRED,
    extensions: params.intermediate?.withKeyDescription ? keyDescriptionExtensions : [],
  })
  const leafIssuerName = params.leafNamesAnotherIssuer
    ? nameOf(COMMON_NAME, OTHER_INTERMEDIATE_NAME)
    : intermediateName
  const leaf = issueCertificate({
    subject: nameOf(COMMON_NAME, 'Android Keystore Key'),
    publicKey: params.publicKey,
    issuer: { name: leafIssuerName, privateKey: intermediateKeys.privateKey },
    isAuthority: false,
    notAfter: params.leafExpired ? EXPIRED : NOT_EXPIRED,
    extensions: keyDescriptionExtensions,
  })
  return [leaf, intermediate, params.root.certificate].map((certificate) =>
    certificate.raw.toString('base64'),
  )
}

export { SecurityLevel, VerifiedBootState } from '@peculiar/asn1-android'
