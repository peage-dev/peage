export function flipLastByte(bytes: Uint8Array): Uint8Array {
  const flipped = new Uint8Array(bytes)
  flipped.set([(bytes.at(-1) ?? 0) ^ 0xff], bytes.length - 1)
  return flipped
}
