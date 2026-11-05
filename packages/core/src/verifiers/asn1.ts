import { type BaseBlock, OctetString, Sequence, fromBER } from 'asn1js'

export function decodeAsn1(bytes: Uint8Array, name: string): BaseBlock {
  const { offset, result } = fromBER(bytes)
  if (offset !== bytes.length) {
    throw new Error(`${name} is not a complete ASN.1 value`)
  }
  return result
}

export function sequenceItems(block: BaseBlock | undefined, name: string): BaseBlock[] {
  if (!(block instanceof Sequence)) {
    throw new Error(`${name} is not a sequence`)
  }
  return block.valueBlock.value
}

/** asn1js leaves the bytes of a constructed (segmented) OCTET STRING out of `valueHexView`. */
export function bytesOf(block: BaseBlock | undefined, name: string): Uint8Array {
  if (!(block instanceof OctetString) || block.idBlock.isConstructed) {
    throw new Error(`${name} is not a primitive octet string`)
  }
  return block.valueBlock.valueHexView
}
