import { isRecord } from '@peage/protocol'

import type { ServiceAccount } from './types.ts'

export function assertValidServiceAccount(
  value: unknown,
  variableName: string,
): asserts value is ServiceAccount {
  if (
    !isRecord(value) ||
    typeof value.client_email !== 'string' ||
    typeof value.private_key !== 'string' ||
    typeof value.token_uri !== 'string'
  ) {
    throw new Error(`${variableName} is not a service account JSON key`)
  }
}

export function assertUploadKeystoreConfigured(variableNames: string[]): void {
  const missingVariables = variableNames.filter((variable) => !process.env[variable])
  if (missingVariables.length > 0) {
    throw new Error(`Set the upload keystore variables: ${missingVariables.join(', ')}`)
  }
}

export function assertValidBundle(value: unknown): asserts value is { versionCode: number } {
  if (!isRecord(value) || typeof value.versionCode !== 'number') {
    throw new Error('Play returned a bundle without a versionCode')
  }
}

export function assertValidAccessTokenResponse(
  value: unknown,
): asserts value is { access_token: string } {
  if (!isRecord(value) || typeof value.access_token !== 'string') {
    throw new Error('Access token response has no access_token')
  }
}

export function assertValidEdit(value: unknown): asserts value is { id: string } {
  if (!isRecord(value) || typeof value.id !== 'string') {
    throw new Error('Edit response has no id')
  }
}

export function assertValidBundleListing(value: unknown): asserts value is Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error('Bundle listing is not a JSON object')
  }
}
