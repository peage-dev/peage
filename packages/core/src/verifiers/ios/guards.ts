export function isByteArray(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array
}

export function isByteArrayList(value: unknown): value is Uint8Array[] {
  return Array.isArray(value) && value.every(isByteArray)
}

/** cbor2 decodes a CBOR map to a plain object only when every key is a text string; otherwise to a `Map`. */
export function isTextKeyedMap(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' && value !== null && Object.getPrototypeOf(value) === Object.prototype
  )
}
