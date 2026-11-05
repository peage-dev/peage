import { isRecord } from '@peage/protocol'

import type { StagedVersion } from './types.ts'

export function isStagedVersion(value: unknown): value is StagedVersion {
  return (
    isRecord(value) &&
    typeof value.id === 'string' &&
    typeof value.packageName === 'string' &&
    typeof value.version === 'string'
  )
}
