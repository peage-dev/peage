import {
  type BaseBlock,
  Boolean as AsnBoolean,
  Constructed,
  Integer,
  OctetString,
  Sequence,
  Set as AsnSet,
  fromBER,
} from 'asn1js'

import type { AttestationApplicationId, AuthorizationList, KeyDescription } from './types.ts'

import {
  ASN1_TAG_CLASS_CONTEXT,
  KEY_DESCRIPTION_TAG_ATTESTATION_APPLICATION_ID,
  KEY_DESCRIPTION_TAG_ORIGIN,
  KEY_DESCRIPTION_TAG_ROOT_OF_TRUST,
} from './constants.ts'

function decodeAsn1(bytes: Uint8Array, name: string): BaseBlock {
  const { offset, result } = fromBER(bytes)
  if (offset !== bytes.length) {
    throw new Error(`Key attestation ${name} is not a complete ASN.1 value`)
  }
  return result
}

function sequenceItems(block: BaseBlock | undefined, name: string): BaseBlock[] {
  if (!(block instanceof Sequence)) {
    throw new Error(`Key attestation ${name} is not a sequence`)
  }
  return block.valueBlock.value
}

function setItems(block: BaseBlock | undefined, name: string): BaseBlock[] {
  if (!(block instanceof AsnSet)) {
    throw new Error(`Key attestation ${name} is not a set`)
  }
  return block.valueBlock.value
}

/**
 * Also reads ENUMERATED, which asn1js models as an Integer. asn1js decodes an
 * integer too large for a number as 0, with a warning.
 */
function integerOf(block: BaseBlock | undefined, name: string): number {
  if (!(block instanceof Integer)) {
    throw new Error(`Key attestation ${name} is not an integer`)
  }
  if (block.valueBlock.warnings.length > 0) {
    throw new Error(`Key attestation ${name} is too large`)
  }
  return block.valueBlock.valueDec
}

function bytesOf(block: BaseBlock | undefined, name: string): Uint8Array {
  if (!(block instanceof OctetString)) {
    throw new Error(`Key attestation ${name} is not an octet string`)
  }
  return block.valueBlock.valueHexView
}

function booleanOf(block: BaseBlock | undefined, name: string): boolean {
  if (!(block instanceof AsnBoolean)) {
    throw new Error(`Key attestation ${name} is not a boolean`)
  }
  return block.valueBlock.value
}

function parseRootOfTrust(block: BaseBlock | undefined): AuthorizationList['rootOfTrust'] {
  const [_verifiedBootKey, deviceLocked, verifiedBootState] = sequenceItems(block, 'rootOfTrust')
  return {
    deviceLocked: booleanOf(deviceLocked, 'deviceLocked'),
    verifiedBootState: integerOf(verifiedBootState, 'verifiedBootState'),
  }
}

/** The OCTET STRING wraps DER: SEQUENCE { SET OF { packageName, version }, SET OF digest }. */
function parseAttestationApplicationId(block: BaseBlock | undefined): AttestationApplicationId {
  const applicationId = decodeAsn1(bytesOf(block, 'attestationApplicationId'), 'application id')
  const [packageInfos, signatureDigests] = sequenceItems(applicationId, 'attestationApplicationId')
  return {
    packageNames: setItems(packageInfos, 'packageInfos').map((packageInfo) => {
      const [packageName] = sequenceItems(packageInfo, 'packageInfo')
      return new TextDecoder().decode(bytesOf(packageName, 'packageName'))
    }),
    signatureDigests: setItems(signatureDigests, 'signatureDigests').map((digest) =>
      bytesOf(digest, 'signatureDigest'),
    ),
  }
}

function parseAuthorizationList(block: BaseBlock | undefined, name: string): AuthorizationList {
  const list: AuthorizationList = {}
  for (const entry of sequenceItems(block, name)) {
    if (!(entry instanceof Constructed) || entry.idBlock.tagClass !== ASN1_TAG_CLASS_CONTEXT) {
      throw new Error(`Key attestation ${name} has an untagged entry`)
    }
    const [value] = entry.valueBlock.value
    switch (entry.idBlock.tagNumber) {
      case KEY_DESCRIPTION_TAG_ORIGIN:
        list.origin = integerOf(value, 'origin')
        break
      case KEY_DESCRIPTION_TAG_ROOT_OF_TRUST:
        list.rootOfTrust = parseRootOfTrust(value)
        break
      case KEY_DESCRIPTION_TAG_ATTESTATION_APPLICATION_ID:
        list.attestationApplicationId = parseAttestationApplicationId(value)
        break
    }
  }
  return list
}

export function parseKeyDescription(der: Uint8Array): KeyDescription {
  const [
    _attestationVersion,
    attestationSecurityLevel,
    _keyMintVersion,
    keySecurityLevel,
    attestationChallenge,
    _uniqueId,
    softwareEnforced,
    hardwareEnforced,
  ] = sequenceItems(decodeAsn1(der, 'key description'), 'key description')
  return {
    attestationSecurityLevel: integerOf(attestationSecurityLevel, 'attestationSecurityLevel'),
    keySecurityLevel: integerOf(keySecurityLevel, 'keySecurityLevel'),
    attestationChallenge: bytesOf(attestationChallenge, 'attestationChallenge'),
    softwareEnforced: parseAuthorizationList(softwareEnforced, 'softwareEnforced'),
    hardwareEnforced: parseAuthorizationList(hardwareEnforced, 'hardwareEnforced'),
  }
}
