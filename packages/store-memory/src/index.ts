import type { AttestedKeyRecord, IssuedChallenge, PeageStore } from '@peage/core'

/** A `PeageStore` that can also delete key records. */
export type MemoryStore = PeageStore & {
  /** Deletes the record for `keyId`, if any. */
  deleteAttestedKey(key: { keyId: string }): Promise<void>
}

/** For development and tests: state lives in the process and is lost on restart. */
export function createMemoryStore(): MemoryStore {
  const challenges = new Map<string, IssuedChallenge>()
  const attestedKeys = new Map<string, AttestedKeyRecord>()

  function deleteExpiredChallengesOldestFirst(): void {
    const now = Date.now()
    for (const [key, challenge] of challenges) {
      if (challenge.expiresAt > now) {
        return
      }
      challenges.delete(key)
    }
  }

  return {
    async saveChallenge(challenge) {
      deleteExpiredChallengesOldestFirst()
      challenges.set(`${challenge.platform}:${challenge.value}`, challenge)
    },
    async takeChallenge({ value, platform }) {
      const key = `${platform}:${value}`
      const challenge = challenges.get(key) ?? null
      challenges.delete(key)
      return challenge
    },
    async saveAttestedKey(record) {
      attestedKeys.set(record.keyId, record)
    },
    async loadAttestedKey({ keyId }) {
      return attestedKeys.get(keyId) ?? null
    },
    async deleteAttestedKey({ keyId }) {
      attestedKeys.delete(keyId)
    },
  }
}
