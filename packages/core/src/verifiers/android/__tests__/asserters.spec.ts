import { describe, expect, it } from 'vitest'

import { assertNotRevoked } from '../asserters.ts'

const CHAIN_SERIAL_NUMBERS = ['5a9c1d', '38826676065899685f6', 'f92009e853b6b045']

describe('assertNotRevoked', () => {
  it('rejects a chain containing a revoked certificate', () => {
    const revoked = new Set(['38826676065899685f6'])
    expect(() => assertNotRevoked(CHAIN_SERIAL_NUMBERS, revoked)).toThrow(/revoked/)
  })

  it('accepts a chain with no revoked certificate', () => {
    expect(() => assertNotRevoked(CHAIN_SERIAL_NUMBERS, new Set(['1234']))).not.toThrow()
  })
})
