import { decode } from 'cbor2'

/** Rejects integers and lengths not in their shortest encoding, duplicate map keys, indefinite lengths and bytes after the first data item; tags stay undecoded cbor2 `Tag` objects. */
export function decodeStrictCbor(bytes: Uint8Array): unknown {
  return decode(bytes, {
    requirePreferred: true,
    rejectDuplicateKeys: true,
    rejectStreaming: true,
    ignoreGlobalTags: true,
  })
}
