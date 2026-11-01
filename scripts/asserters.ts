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

export function assertValidPackageJson(value: unknown): asserts value is { version: string } {
  if (!isRecord(value) || typeof value.version !== 'string') {
    throw new Error('package.json has no version')
  }
}

export function assertOnMain(branch: string): void {
  if (branch !== 'main') {
    throw new Error(`Release from main, not ${branch || 'a detached HEAD'}`)
  }
}

export function assertCleanWorkingTree(status: string): void {
  if (status !== '') {
    throw new Error('Commit or stash your changes first')
  }
}

export function assertPushed(localCommit: string, remoteCommit: string): void {
  if (localCommit !== remoteCommit) {
    throw new Error(`Local main is at ${localCommit}, GitHub's at ${remoteCommit}`)
  }
}

export function assertCiPassed(runs: unknown, commit: string): void {
  const [latestRun] = Array.isArray(runs) ? runs : []
  if (
    !isRecord(latestRun) ||
    latestRun.status !== 'completed' ||
    latestRun.conclusion !== 'success'
  ) {
    throw new Error(`CI has not passed on ${commit}`)
  }
}

export function assertSomethingToRelease(missingPackages: string[], version: string): void {
  if (missingPackages.length === 0) {
    throw new Error(`${version} is already on npm; run pnpm changeset version first`)
  }
}

export function assertRunStarted(
  runId: string | undefined,
  workflow: string,
): asserts runId is string {
  if (runId === undefined) {
    throw new Error(`Could not start ${workflow}, or gh did not print the run URL`)
  }
}

export function assertAllOnNpm(missingPackages: string[], version: string): void {
  if (missingPackages.length > 0) {
    throw new Error(
      `${missingPackages.join(', ')} not on npm at ${version}; approve them, then run the GitHub release workflow`,
    )
  }
}
