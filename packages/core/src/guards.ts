import type { AttestationEnvironment } from './types.ts'

/** Whether the value is an attestation environment Péage supports. */
export function isAttestationEnvironment(value: unknown): value is AttestationEnvironment {
  return value === 'production' || value === 'development'
}
