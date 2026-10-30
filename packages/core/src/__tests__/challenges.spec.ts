import { describe, expect, it } from 'vitest'

import { getRandomChallenge } from '../challenges.ts'

describe('getRandomChallenge', () => {
  it('returns 32 random bytes as 43 base64url characters', () => {
    expect(getRandomChallenge()).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })

  it('returns a distinct value on each call', () => {
    const values = new Set<string>()
    for (let call = 0; call < 10; call++) {
      values.add(getRandomChallenge())
    }
    expect(values.size).toBe(10)
  })
})
