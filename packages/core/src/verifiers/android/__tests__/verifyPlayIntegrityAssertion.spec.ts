import { newDeviceKey, signPlayIntegrityRequest } from '@peage/tests'
import { generateKeyPairSync } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { AssertionInput } from '../../types.ts'

import { verifyPlayIntegrityAssertion } from '../verifyPlayIntegrityAssertion.ts'

const FROZEN_TIME = new Date('2026-05-01T12:00:00Z')
const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })

function signedInput(): AssertionInput {
  const request = {
    method: 'POST',
    path: '/api/protected?page=1',
    body: new TextEncoder().encode('{"hello":"world"}'),
  }
  return { ...request, publicKey, assertion: signPlayIntegrityRequest({ privateKey, ...request }) }
}

describe('verifyPlayIntegrityAssertion', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(FROZEN_TIME)
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('accepts a Keystore signature over the clientDataHash', () => {
    expect(() => verifyPlayIntegrityAssertion(signedInput())).not.toThrow()
  })

  it('accepts a signature from the previous bucket', () => {
    const input = signedInput()
    vi.setSystemTime(FROZEN_TIME.getTime() + 30_000)
    expect(() => verifyPlayIntegrityAssertion(input)).not.toThrow()
  })

  it('rejects a signature two buckets old', () => {
    const input = signedInput()
    vi.setSystemTime(FROZEN_TIME.getTime() + 60_000)
    expect(() => verifyPlayIntegrityAssertion(input)).toThrow(/recent time bucket/)
  })

  it('rejects a body that differs from what was signed', () => {
    const input = { ...signedInput(), body: new TextEncoder().encode('{"hello":"tampered"}') }
    expect(() => verifyPlayIntegrityAssertion(input)).toThrow(/recent time bucket/)
  })

  it('rejects a signature from another key', () => {
    const otherKey = newDeviceKey()
    const input = { ...signedInput(), publicKey: otherKey }
    expect(() => verifyPlayIntegrityAssertion(input)).toThrow(/recent time bucket/)
  })
})
