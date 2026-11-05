import { execFileSync, spawnSync } from 'node:child_process'
import { setTimeout as sleep } from 'node:timers/promises'

import {
  assertAllOnNpm,
  assertCiPassed,
  assertCleanWorkingTree,
  assertOnMain,
  assertPushed,
  assertRunStarted,
  assertValidPackageJson,
} from './asserters.ts'

const REPOSITORY = 'peage-dev/peage'
const PACKAGES = ['protocol', 'core', 'store-memory', 'store-redis', 'express', 'react-native']
const CI_WORKFLOW = 'ci.yml'
const RELEASE_WORKFLOW = 'release.yml'
const GITHUB_RELEASE_WORKFLOW = 'github-releases.yml'
const RUN_URL = /\/actions\/runs\/(\d+)/
const NPM_POLL_INTERVAL_MS = 10_000
const NPM_WAIT_LIMIT_MS = 15 * 60_000

type ReleaseState = 'not staged' | 'staged' | 'on npm' | 'released'

function run(command: string, args: string[]): void {
  execFileSync(command, args, { stdio: 'inherit' })
}

function output(command: string, args: string[]): string {
  const stdout = execFileSync(command, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
  })
  return stdout.trim()
}

function succeeds(command: string, args: string[]): boolean {
  return spawnSync(command, args, { stdio: 'ignore' }).status === 0
}

/** `gh` on the Péage repository. */
function gh(args: string[]): string {
  return output('gh', [...args, '--repo', REPOSITORY])
}

/** A field of the latest run of `workflow` matching `filters`, or '' when there is none. */
function latestRunField(workflow: string, filters: string[], field: string): string {
  const selection = ['--workflow', workflow, ...filters, '--limit', '1']
  const projection = ['--json', field, '--jq', `.[0].${field} // ""`]
  return gh(['run', 'list', ...selection, ...projection])
}

/** All six packages share the version of `@peage/protocol`. */
function versionAt(commit: string): string {
  const packageJson: unknown = JSON.parse(
    output('git', ['show', `${commit}:packages/protocol/package.json`]),
  )
  assertValidPackageJson(packageJson)
  return packageJson.version
}

function lastStagedVersion(): string | undefined {
  const filters = ['--branch', 'main', '--status', 'success']
  const commit = latestRunField(RELEASE_WORKFLOW, filters, 'headSha')
  return commit === '' ? undefined : versionAt(commit)
}

function isOnNpm(name: string, version: string): boolean {
  return succeeds('npm', ['view', `@peage/${name}@${version}`, 'version', '--prefer-online'])
}

function packagesMissingFromNpm(version: string): string[] {
  return PACKAGES.filter((name) => !isOnNpm(name, version))
}

function isReleasedOnGitHub(version: string): boolean {
  return succeeds('gh', ['release', 'view', `v${version}`, '--repo', REPOSITORY])
}

function releaseStateOf(version: string): ReleaseState {
  if (isReleasedOnGitHub(version)) {
    return 'released'
  }
  if (packagesMissingFromNpm(version).length === 0) {
    return 'on npm'
  }
  return lastStagedVersion() === version ? 'staged' : 'not staged'
}

function assertReadyToRelease(commit: string): void {
  assertOnMain(output('git', ['branch', '--show-current']))
  assertCleanWorkingTree(output('git', ['status', '--porcelain']))
  assertPushed(commit, output('gh', ['api', `repos/${REPOSITORY}/commits/main`, '--jq', '.sha']))
  assertCiPassed(latestRunField(CI_WORKFLOW, ['--commit', commit], 'conclusion'), commit)
}

function watchRun(runId: string): void {
  run('gh', ['run', 'watch', runId, '--repo', REPOSITORY, '--exit-status', '--compact'])
}

function runWorkflow(workflow: string): void {
  const dispatched = gh(['workflow', 'run', workflow, '--ref', 'main'])
  console.log(dispatched)
  const runId = RUN_URL.exec(dispatched)?.[1]
  assertRunStarted(runId, workflow)
  watchRun(runId)
}

function ignoreInterrupt(): void {}

/** Ctrl-C stops only the running command, so the logout still happens. */
function withNpmLogin(task: () => void): void {
  process.on('SIGINT', ignoreInterrupt)
  try {
    run('npm', ['login'])
    try {
      task()
    } finally {
      run('npm', ['logout'])
    }
  } finally {
    process.off('SIGINT', ignoreInterrupt)
  }
}

function approveStagedVersions(): void {
  try {
    run('pnpm', ['stage', 'approve'])
  } catch (error) {
    throw new Error(
      "Not every version was approved. If npm said its review hasn't finished, run pnpm release again in a minute.",
      { cause: error },
    )
  }
}

async function waitUntilOnNpm(version: string): Promise<void> {
  const deadline = Date.now() + NPM_WAIT_LIMIT_MS
  let missing = packagesMissingFromNpm(version)
  while (missing.length > 0 && Date.now() < deadline) {
    console.log(`Waiting for npm to serve ${version} of ${missing.join(', ')}`)
    // oxlint-disable-next-line no-await-in-loop
    await sleep(NPM_POLL_INTERVAL_MS)
    missing = packagesMissingFromNpm(version)
  }
  assertAllOnNpm(missing, version)
}

function stage(version: string): void {
  runWorkflow(RELEASE_WORKFLOW)
  console.log(`Staged ${version}. npm reviews it for a few minutes; then run pnpm release again.`)
}

async function publish(version: string): Promise<void> {
  withNpmLogin(approveStagedVersions)
  await waitUntilOnNpm(version)
  runWorkflow(GITHUB_RELEASE_WORKFLOW)
}

/** Each run takes the release one step further: stage, then approve and announce it. */
async function main(): Promise<void> {
  const commit = output('git', ['rev-parse', 'HEAD'])
  assertReadyToRelease(commit)
  const version = versionAt(commit)
  const state = releaseStateOf(version)
  console.log(`${version} is ${state}`)

  switch (state) {
    case 'not staged':
      stage(version)
      break
    case 'staged':
      await publish(version)
      break
    case 'on npm':
      runWorkflow(GITHUB_RELEASE_WORKFLOW)
      break
    case 'released':
      console.log('Nothing to do; run pnpm changeset version for the next one.')
      break
  }
}

await main()
