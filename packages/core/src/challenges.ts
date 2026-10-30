import { toBase64url } from '@peage/protocol'

const CHALLENGE_BYTES = 32

export const CHALLENGE_TTL_MS: number = 5 * 60 * 1000

export function getRandomChallenge(): string {
  return toBase64url(crypto.getRandomValues(new Uint8Array(CHALLENGE_BYTES)))
}
