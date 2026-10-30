import { newDeviceKey } from '@peage/tests'
import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'

import { assertKeyIdMatches } from '../asserters.ts'
import { IOS_27_DEVICE } from '../ios/__tests__/deviceFixtures.ts'

describe('assertKeyIdMatches', () => {
  it('accepts a real device keyId against its public key', () => {
    const { publicKey, keyId } = IOS_27_DEVICE
    expect(() => assertKeyIdMatches(publicKey, keyId)).not.toThrow()
  })

  it('rejects a keyId hashed from a different key', () => {
    const otherKey = newDeviceKey()
    expect(() => assertKeyIdMatches(otherKey, IOS_27_DEVICE.keyId)).toThrow(/does not match/)
  })

  it('rejects a key that is not P-256', () => {
    const p384Key = generateKeyPairSync('ec', { namedCurve: 'P-384' }).publicKey
    expect(() => assertKeyIdMatches(p384Key, IOS_27_DEVICE.keyId)).toThrow(/not P-256/)
  })
})
