import { describe, expect, it } from 'vitest'

import { assertCanonicalKeyId } from '../asserters.ts'
import { IOS_27_DEVICE } from '../verifiers/ios/__tests__/deviceFixtures.ts'

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

/** The same 32 bytes with the unused low bits of the last character set. */
function withTrailingBitsSet(keyId: string): string {
  const lastCharacter = keyId.at(-2) ?? ''
  const shifted = BASE64_ALPHABET[BASE64_ALPHABET.indexOf(lastCharacter) + 1] ?? ''
  return `${keyId.slice(0, -2)}${shifted}=`
}

describe('assertCanonicalKeyId', () => {
  it('accepts a real device keyId', () => {
    expect(() => assertCanonicalKeyId(IOS_27_DEVICE.keyId)).not.toThrow()
  })

  it('rejects other spellings of the same 32 bytes', () => {
    const { keyId } = IOS_27_DEVICE
    const spellings = [
      keyId.replace(/=$/, ''),
      withTrailingBitsSet(keyId),
      `${keyId.slice(0, 4)} ${keyId.slice(4)}`,
      keyId.replace(/\+/g, '-').replace(/\//g, '_'),
    ]
    for (const spelling of spellings) {
      expect(() => assertCanonicalKeyId(spelling)).toThrow(/not canonical/)
    }
  })
})
