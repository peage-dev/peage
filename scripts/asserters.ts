import { isRecord } from '@peage/protocol'

import type { ServiceAccount, StagedVersion } from './types.ts'

import { isStagedVersion } from './guards.ts'

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

export function assertValidStagedVersions(value: unknown): asserts value is StagedVersion[] {
  if (!Array.isArray(value) || !value.every(isStagedVersion)) {
    throw new Error('npm returned staged versions without the expected fields')
  }
}

export function assertValidPackageJson(value: unknown): asserts value is { version: string } {
  if (!isRecord(value) || typeof value.version !== 'string') {
    throw new Error('package.json has no version')
  }
}

export function assertFound(value: string | undefined, message: string): asserts value is string {
  if (!value) {
    throw new Error(message)
  }
}

export function assertOnlyVersionStaged(staged: StagedVersion[], version: string): void {
  const others = staged.filter((candidate) => candidate.version !== version)
  if (others.length > 0) {
    const labels = others.map(({ packageName, version: other }) => `${packageName}@${other}`)
    throw new Error(`Releasing ${version}, but npm also has ${labels.join(', ')} staged`)
  }
}

export function assertAllStaged(missing: string[], version: string): void {
  if (missing.length > 0) {
    throw new Error(`${version} of ${missing.join(', ')} is neither on npm nor staged`)
  }
}

export function assertNothingStaged(staged: StagedVersion[], commit: string): void {
  if (staged.length > 0) {
    const rejections = staged.map(({ id }) => `  npm stage reject ${id}`).join('\n')
    throw new Error(
      `These were staged, but not by a successful release.yml run on ${commit}. Reject them, then run pnpm release again:\n  npm login\n${rejections}\n  npm logout`,
    )
  }
}

/** `status` compares main to the commit: main is ahead of it, or is it. */
export function assertOnMain(status: string, commit: string): void {
  if (status !== 'ahead' && status !== 'identical') {
    throw new Error(`${commit} is not on main on GitHub`)
  }
}

export function assertTagOn(taggedCommit: string, tag: string, commit: string): void {
  if (taggedCommit !== commit) {
    throw new Error(
      `${tag} is on ${taggedCommit}, not ${commit}. Run pnpm changeset version for the next version, or delete the tag if ${tag} never got released.`,
    )
  }
}
