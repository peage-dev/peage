import { concatBytes } from '@peage/protocol'
import { encode } from 'cbor2'

const CBOR_MAP_HEADER = 0xa0
const CBOR_TEXT_STRING_ONE_BYTE_LENGTH = 0x78
const CBOR_INDEFINITE_BYTE_STRING_START = 0x5f
const CBOR_BREAK = 0xff

/** A CBOR map of encoded keys and values written in the given order, duplicates included (fewer than 24 entries). */
export function encodeCborMapOfEncodedEntries(
  entries: [encodedKey: Uint8Array, encodedValue: Uint8Array][],
): Uint8Array {
  return concatBytes(Uint8Array.of(CBOR_MAP_HEADER + entries.length), ...entries.flat())
}

/** A CBOR map with text keys written in the given order, duplicates included (fewer than 24 entries). */
export function encodeCborMap(entries: [key: string, encodedValue: Uint8Array][]): Uint8Array {
  return encodeCborMapOfEncodedEntries(
    entries.map(([key, encodedValue]) => [encode(key), encodedValue]),
  )
}

/** The text as a CBOR text string with its length in a following byte, even when it fits in the header. */
export function encodeLongFormTextString(text: string): Uint8Array {
  const bytes = new TextEncoder().encode(text)
  return concatBytes(Uint8Array.of(CBOR_TEXT_STRING_ONE_BYTE_LENGTH, bytes.length), bytes)
}

/** The bytes as an indefinite-length CBOR byte string of two chunks. */
export function encodeIndefiniteByteString(bytes: Uint8Array): Uint8Array {
  const middle = Math.floor(bytes.length / 2)
  return concatBytes(
    Uint8Array.of(CBOR_INDEFINITE_BYTE_STRING_START),
    encode(bytes.subarray(0, middle)),
    encode(bytes.subarray(middle)),
    Uint8Array.of(CBOR_BREAK),
  )
}
