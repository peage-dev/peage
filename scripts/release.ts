import { execFileSync, spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { setTimeout as sleep } from 'node:timers/promises'

import {
  assertAllOnNpm,
  assertCiPassed,
  assertCleanWorkingTree,
  assertOnMain,
  assertPushed,
  assertRunStarted,
  assertSomethingToRelease,
  assertValidPackageJson,
} from './asserters.ts'

const REPOSITORY = 'peage-dev/peage'
const PACKAGES = ['protocol', 'core', 'store-memory', 'store-redis', 'express', 'react-native']
const RUN_URL = /\/actions\/runs\/(\d+)/
const NPM_POLL_INTERVAL_MS = 10_000
const NPM_WAIT_LIMIT_MS = 15 * 60_000

function run(command: string, args: string[]): void {
  execFileSync(command, args, { stdio: 'inherit' })
}

function output(command: string, args: string[]): string {
  return execFileSync(command, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
  }).trim()
}

function readVersion(): string {
  const packageJson: unknown = JSON.parse(
    readFileSync(new URL('../packages/protocol/package.json', import.meta.url), 'utf8'),
  )
  assertValidPackageJson(packageJson)
  return packageJson.version
}

function isOnNpm(packageName: string, version: string): boolean {
  const result = spawnSync(
    'npm',
    ['view', `@peage/${packageName}@${version}`, 'version', '--prefer-online'],
    {
      encoding: 'utf8',
    },
  )
  return result.stdout.trim() === version
}

function packagesMissingFromNpm(version: string): string[] {
  return PACKAGES.filter((packageName) => !isOnNpm(packageName, version))
}

function assertReadyToRelease(commit: string): void {
  assertOnMain(output('git', ['branch', '--show-current']))
  assertCleanWorkingTree(output('git', ['status', '--porcelain']))
  assertPushed(commit, output('gh', ['api', `repos/${REPOSITORY}/commits/main`, '--jq', '.sha']))
  const ciRuns: unknown = JSON.parse(
    output('gh', [
      'run',
      'list',
      '--repo',
      REPOSITORY,
      '--workflow',
      'ci.yml',
      '--commit',
      commit,
      '--json',
      'status,conclusion',
      '--limit',
      '1',
    ]),
  )
  assertCiPassed(ciRuns, commit)
}

function runWorkflow(workflow: string): void {
  const dispatch = spawnSync(
    'gh',
    ['workflow', 'run', workflow, '--repo', REPOSITORY, '--ref', 'main'],
    {
      encoding: 'utf8',
    },
  )
  const dispatchOutput = dispatch.stdout + dispatch.stderr
  process.stdout.write(dispatchOutput)
  const runId = RUN_URL.exec(dispatchOutput)?.[1]
  assertRunStarted(runId, workflow)
  run('gh', ['run', 'watch', runId, '--repo', REPOSITORY, '--exit-status', '--compact'])
}

function ignoreInterrupt(): void {}

function approveStagedVersions(): void {
  // Ctrl-C then only stops the running command, so the logout below still runs.
  process.on('SIGINT', ignoreInterrupt)
  try {
    run('npm', ['login'])
    try {
      run('pnpm', ['stage', 'approve'])
    } finally {
      run('npm', ['logout'])
    }
  } finally {
    process.off('SIGINT', ignoreInterrupt)
  }
}

async function waitUntilOnNpm(version: string): Promise<void> {
  const deadline = Date.now() + NPM_WAIT_LIMIT_MS
  let missing = packagesMissingFromNpm(version)
  while (missing.length > 0 && Date.now() < deadline) {
    console.log(`Waiting for npm to serve ${version} of: ${missing.join(', ')}`)
    // oxlint-disable-next-line no-await-in-loop
    await sleep(NPM_POLL_INTERVAL_MS)
    missing = packagesMissingFromNpm(version)
  }
  assertAllOnNpm(missing, version)
}

async function main(): Promise<void> {
  const commit = output('git', ['rev-parse', 'HEAD'])
  assertReadyToRelease(commit)
  const version = readVersion()
  assertSomethingToRelease(packagesMissingFromNpm(version), version)

  console.log(`Releasing ${version} from ${commit}`)
  runWorkflow('release.yml')
  approveStagedVersions()
  await waitUntilOnNpm(version)
  runWorkflow('github-releases.yml')
}

await main()
