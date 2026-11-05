import { execFileSync, spawnSync } from 'node:child_process'

import type { StagedVersion } from './types.ts'

import {
  assertAllStaged,
  assertFound,
  assertNothingStaged,
  assertOnMain,
  assertOnlyVersionStaged,
  assertTagOn,
  assertValidPackageJson,
  assertValidStagedVersions,
} from './asserters.ts'

const REPOSITORY = 'peage-dev/peage'
/** Dependencies first, the order they are approved in. */
const PACKAGES = ['protocol', 'core', 'store-memory', 'store-redis', 'express', 'react-native'].map(
  (name) => `@peage/${name}`,
)
const RUN_URL = /\/actions\/runs\/(\d+)/
const REVIEW_PENDING = /automated review hasn't finished/

function run(command: string, args: string[]): void {
  execFileSync(command, args, { stdio: 'inherit' })
}

function output(command: string, args: string[]): string {
  return execFileSync(command, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
  }).trim()
}

/** `gh` on the Péage repository. */
function gh(args: string[]): string {
  return output('gh', [...args, '--repo', REPOSITORY])
}

/** Fails unless the run succeeds; returns at once for a finished run. */
function watchRun(runId: string): void {
  run('gh', ['run', 'watch', runId, '--repo', REPOSITORY, '--exit-status', '--compact'])
}

function dispatch(workflow: string, tag: string): string {
  const dispatched = gh(['workflow', 'run', workflow, '--ref', tag])
  const runId = RUN_URL.exec(dispatched)?.[1]
  assertFound(runId, `gh did not print the ${workflow} run URL`)
  return runId
}

function waitForCi(commit: string): void {
  const filters = ['--workflow', 'ci.yml', '--event', 'push', '--commit', commit, '--limit', '1']
  const projection = ['--json', 'databaseId', '--jq', '.[0].databaseId // ""']
  const runId = gh(['run', 'list', ...filters, ...projection])
  assertFound(runId, `No CI run for ${commit} yet`)
  watchRun(runId)
}

/** All six packages share the version of `@peage/protocol`. */
function versionAt(commit: string): string {
  const packageJson: unknown = JSON.parse(
    output('git', ['show', `${commit}:packages/protocol/package.json`]),
  )
  assertValidPackageJson(packageJson)
  return packageJson.version
}

/** Creates the tag on GitHub, or checks it's already on the commit. */
function tagCommit(tag: string, commit: string): void {
  const ref = `repos/${REPOSITORY}/git/ref/tags/${tag}`
  const existing = spawnSync('gh', ['api', ref, '--jq', '.object.sha'], { encoding: 'utf8' })
  if (existing.status === 0) {
    assertTagOn(existing.stdout.trim(), tag, commit)
  } else {
    const fields = ['--raw-field', `ref=refs/tags/${tag}`, '--raw-field', `sha=${commit}`]
    output('gh', ['api', `repos/${REPOSITORY}/git/refs`, ...fields, '--silent'])
  }
}

function isOnNpm(name: string, version: string): boolean {
  return spawnSync('npm', ['view', `${name}@${version}`, 'version', '--prefer-online']).status === 0
}

/**
 * npm stages a version only once, so once release.yml succeeded on the commit, everything staged
 * at its version came from that commit.
 */
function wasStagedFrom(commit: string): boolean {
  const filters = ['--workflow', 'release.yml', '--commit', commit, '--status', 'success']
  const projection = ['--limit', '1', '--json', 'databaseId', '--jq', 'length']
  return gh(['run', 'list', ...filters, ...projection]) === '1'
}

/** Refuses other staged `@peage/*` versions, so it never approves one you didn't release. */
function stagedVersionsOf(version: string): StagedVersion[] {
  const staged: unknown = JSON.parse(output('npm', ['stage', 'list', '--json']))
  assertValidStagedVersions(staged)
  const ours = PACKAGES.flatMap((name) => staged.filter(({ packageName }) => packageName === name))
  assertOnlyVersionStaged(ours, version)
  return ours
}

/** False while npm's automated review of the version runs; npm has no way to ask about it. */
function approve({ id, packageName, version }: StagedVersion, otpReference: string): boolean {
  const result = spawnSync('npm', ['stage', 'approve', id], {
    encoding: 'utf8',
    // 2FA codes last 30 seconds, so each attempt reads a fresh one.
    env: { ...process.env, npm_config_otp: output('op', ['read', otpReference]) },
  })
  const npmOutput = `${result.stdout}${result.stderr}`
  if (result.status !== 0 && !REVIEW_PENDING.test(npmOutput)) {
    throw new Error(`npm could not approve ${packageName}@${version}:\n${npmOutput}`)
  }
  return result.status === 0
}

function stageAndApprove(
  commit: string,
  tag: string,
  version: string,
  unpublished: string[],
  otpReference: string,
): void {
  if (!wasStagedFrom(commit)) {
    assertNothingStaged(stagedVersionsOf(version), commit)
    watchRun(dispatch('release.yml', tag))
  }
  const staged = stagedVersionsOf(version)
  const missing = unpublished.filter(
    (name) => !staged.some(({ packageName }) => packageName === name),
  )
  assertAllStaged(missing, version)
  for (const stagedVersion of staged) {
    const label = `${stagedVersion.packageName}@${version}`
    while (!approve(stagedVersion, otpReference)) {
      console.log(`npm is still reviewing ${label}; trying again in 30 seconds`)
      run('sleep', ['30'])
    }
    console.log(`Approved ${label}`)
  }
}

/** Releases the checked-out commit, which must be on main and have passed CI, from its version tag. */
function main(): void {
  const otpReference = process.env.NPM_OTP_REFERENCE
  assertFound(
    otpReference,
    'Set NPM_OTP_REFERENCE in .env to the 1Password reference of your npm 2FA code, e.g. op://Private/npm/totp?attribute=otp',
  )
  const commit = output('git', ['rev-parse', 'HEAD'])
  const comparison = `repos/${REPOSITORY}/compare/${commit}...main`
  assertOnMain(output('gh', ['api', comparison, '--jq', '.status']), commit)
  waitForCi(commit)
  const version = versionAt(commit)
  const tag = `v${version}`
  tagCommit(tag, commit)
  const unpublished = PACKAGES.filter((name) => !isOnNpm(name, version))
  if (unpublished.length > 0) {
    // Ctrl-C stops the running command, which throws, so the logout still happens.
    process.on('SIGINT', () => {})
    run('npm', ['login'])
    try {
      stageAndApprove(commit, tag, version, unpublished, otpReference)
    } finally {
      run('npm', ['logout'])
    }
  }
  watchRun(dispatch('github-releases.yml', tag))
}

main()
