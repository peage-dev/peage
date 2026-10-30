import { fromBase64 } from '@peage/protocol'
import { type BaseBlock, Constructed, Integer, Sequence, fromBER } from 'asn1js'
import { X509Certificate } from 'node:crypto'
import { describe, expect, it } from 'vitest'

import { getCertificateExtension } from '../../certificates.ts'
import {
  ASN1_TAG_CLASS_CONTEXT,
  KEY_DESCRIPTION_OID,
  KEY_DESCRIPTION_TAG_ORIGIN,
} from '../constants.ts'
import { parseKeyDescription } from '../keyDescription.ts'
import { PIXEL_3A_KEY_ATTESTATION, PIXEL_9A_KEY_ATTESTATION } from './deviceFixtures.ts'

function keyDescriptionOf(certificateChain: string[]): Uint8Array {
  const leaf = new X509Certificate(fromBase64(certificateChain[0] ?? ''))
  const extension = getCertificateExtension(leaf.raw, KEY_DESCRIPTION_OID)
  if (!extension) {
    throw new Error('fixture leaf has no key description')
  }
  return extension
}

function contextTagged(tagNumber: number, value: Integer): Constructed {
  return new Constructed({
    idBlock: { tagClass: ASN1_TAG_CLASS_CONTEXT, tagNumber },
    value: [value],
  })
}

function withExtraHardwareEntry(keyDescription: Uint8Array, entry: BaseBlock): Uint8Array {
  const { result } = fromBER(keyDescription)
  if (!(result instanceof Sequence)) {
    throw new Error('fixture key description is not a sequence')
  }
  const fields = result.valueBlock.value
  const hardwareEnforced = fields[7]
  if (!(hardwareEnforced instanceof Sequence)) {
    throw new Error('fixture hardwareEnforced is not a sequence')
  }
  const extended = new Sequence({ value: [...hardwareEnforced.valueBlock.value, entry] })
  return new Uint8Array(new Sequence({ value: [...fields.slice(0, 7), extended] }).toBER())
}

describe('parseKeyDescription', () => {
  it('reads the checked fields of a Keymaster 4 description (Pixel 3a)', () => {
    const description = parseKeyDescription(
      keyDescriptionOf(PIXEL_3A_KEY_ATTESTATION.certificateChain),
    )
    expect(description).toMatchObject({
      attestationSecurityLevel: 1,
      keySecurityLevel: 1,
      softwareEnforced: { attestationApplicationId: { packageNames: ['dev.peage.rnexample'] } },
      hardwareEnforced: { origin: 0, rootOfTrust: { deviceLocked: true, verifiedBootState: 0 } },
    })
  })

  it('reads the checked fields of a KeyMint description (Pixel 9a)', () => {
    const description = parseKeyDescription(
      keyDescriptionOf(PIXEL_9A_KEY_ATTESTATION.certificateChain),
    )
    expect(description).toMatchObject({
      attestationSecurityLevel: 1,
      keySecurityLevel: 1,
      softwareEnforced: { attestationApplicationId: { packageNames: ['dev.peage.rnexample'] } },
      hardwareEnforced: { origin: 0, rootOfTrust: { deviceLocked: true, verifiedBootState: 0 } },
    })
  })

  it('skips tags it does not know', () => {
    const original = keyDescriptionOf(PIXEL_9A_KEY_ATTESTATION.certificateChain)
    const extended = withExtraHardwareEntry(original, contextTagged(799, new Integer({ value: 1 })))
    expect(extended.length).toBeGreaterThan(original.length)
    expect(parseKeyDescription(extended)).toStrictEqual(parseKeyDescription(original))
  })

  it('rejects an integer too large to decode, which asn1js would read as 0', () => {
    const original = keyDescriptionOf(PIXEL_9A_KEY_ATTESTATION.certificateChain)
    const oversized = new Integer({ valueHex: Uint8Array.of(1, 0, 0, 0, 0, 0, 0, 0, 0) })
    const tampered = withExtraHardwareEntry(
      original,
      contextTagged(KEY_DESCRIPTION_TAG_ORIGIN, oversized),
    )
    expect(() => parseKeyDescription(tampered)).toThrow(/origin is too large/)
  })

  it('rejects an authorization list entry that is a plain SEQUENCE, not context-tagged', () => {
    const original = keyDescriptionOf(PIXEL_9A_KEY_ATTESTATION.certificateChain)
    const untagged = new Sequence({ value: [new Integer({ value: 0 })] })
    const tampered = withExtraHardwareEntry(original, untagged)
    expect(() => parseKeyDescription(tampered)).toThrow(/hardwareEnforced has an untagged entry/)
  })

  it('rejects bytes that are not a complete ASN.1 value', () => {
    expect(() => parseKeyDescription(Uint8Array.of(0x30, 0x05, 0x02))).toThrow(
      /not a complete ASN.1 value/,
    )
  })

  it('rejects trailing bytes after the description', () => {
    const original = keyDescriptionOf(PIXEL_3A_KEY_ATTESTATION.certificateChain)
    const padded = new Uint8Array([...original, 0x00])
    expect(() => parseKeyDescription(padded)).toThrow(/not a complete ASN.1 value/)
  })
})
