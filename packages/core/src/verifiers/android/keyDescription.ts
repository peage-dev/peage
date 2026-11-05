import { type BaseBlock, Boolean as AsnBoolean, Constructed, Integer, Set as AsnSet } from 'asn1js'

import type { AttestationApplicationId, AuthorizationList, KeyDescription } from './types.ts'

import { bytesOf, decodeAsn1, sequenceItems } from '../asn1.ts'
import { ASN1_TAG_CLASS_CONTEXT } from '../constants.ts'
import {
  KEY_DESCRIPTION_TAG_ATTESTATION_APPLICATION_ID,
  KEY_DESCRIPTION_TAG_ORIGIN,
  KEY_DESCRIPTION_TAG_ROOT_OF_TRUST,
} from './constants.ts'

function setItems(block: BaseBlock | undefined, name: string): BaseBlock[] {
  if (!(block instanceof AsnSet)) {
    throw new Error(`${name} is not a set`)
  }
  return block.valueBlock.value
}

/**
 * Also reads ENUMERATED, which asn1js models as an Integer. asn1js decodes an
 * integer too large for a number as 0, with a warning.
 */
function integerOf(block: BaseBlock | undefined, name: string): number {
  if (!(block instanceof Integer)) {
    throw new Error(`${name} is not an integer`)
  }
  if (block.valueBlock.warnings.length > 0) {
    throw new Error(`${name} is too large`)
  }
  return block.valueBlock.valueDec
}

function booleanOf(block: BaseBlock | undefined, name: string): boolean {
  if (!(block instanceof AsnBoolean)) {
    throw new Error(`${name} is not a boolean`)
  }
  return block.valueBlock.value
}

function parseRootOfTrust(block: BaseBlock | undefined): AuthorizationList['rootOfTrust'] {
  const [_verifiedBootKey, deviceLocked, verifiedBootState] = sequenceItems(
    block,
    'Key attestation rootOfTrust',
  )
  return {
    deviceLocked: booleanOf(deviceLocked, 'Key attestation deviceLocked'),
    verifiedBootState: integerOf(verifiedBootState, 'Key attestation verifiedBootState'),
  }
}

/** The OCTET STRING wraps DER: SEQUENCE { SET OF { packageName, version }, SET OF digest }. */
function parseAttestationApplicationId(block: BaseBlock | undefined): AttestationApplicationId {
  const applicationId = decodeAsn1(
    bytesOf(block, 'Key attestation attestationApplicationId'),
    'Key attestation application id',
  )
  const [packageInfos, signatureDigests] = sequenceItems(
    applicationId,
    'Key attestation attestationApplicationId',
  )
  return {
    packageNames: setItems(packageInfos, 'Key attestation packageInfos').map((packageInfo) => {
      const [packageName] = sequenceItems(packageInfo, 'Key attestation packageInfo')
      return new TextDecoder().decode(bytesOf(packageName, 'Key attestation packageName'))
    }),
    signatureDigests: setItems(signatureDigests, 'Key attestation signatureDigests').map((digest) =>
      bytesOf(digest, 'Key attestation signatureDigest'),
    ),
  }
}

function parseAuthorizationList(block: BaseBlock | undefined, name: string): AuthorizationList {
  const list: AuthorizationList = {}
  for (const entry of sequenceItems(block, `Key attestation ${name}`)) {
    if (!(entry instanceof Constructed) || entry.idBlock.tagClass !== ASN1_TAG_CLASS_CONTEXT) {
      throw new Error(`Key attestation ${name} has an untagged entry`)
    }
    const [value] = entry.valueBlock.value
    switch (entry.idBlock.tagNumber) {
      case KEY_DESCRIPTION_TAG_ORIGIN:
        list.origin = integerOf(value, 'Key attestation origin')
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
  ] = sequenceItems(
    decodeAsn1(der, 'Key attestation key description'),
    'Key attestation key description',
  )
  return {
    attestationSecurityLevel: integerOf(
      attestationSecurityLevel,
      'Key attestation attestationSecurityLevel',
    ),
    keySecurityLevel: integerOf(keySecurityLevel, 'Key attestation keySecurityLevel'),
    attestationChallenge: bytesOf(attestationChallenge, 'Key attestation attestationChallenge'),
    softwareEnforced: parseAuthorizationList(softwareEnforced, 'softwareEnforced'),
    hardwareEnforced: parseAuthorizationList(hardwareEnforced, 'hardwareEnforced'),
  }
}
