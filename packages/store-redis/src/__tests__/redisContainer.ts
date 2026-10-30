import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const runCommand = promisify(execFile)

const REDIS_IMAGE = 'redis:8-alpine'
const CONTAINER_LIFETIME_SECONDS = 300

export type RedisContainer = {
  url: string
  stop: () => Promise<void>
}

/** Runs Redis in Docker on a free 127.0.0.1 port, for at most five minutes. */
export async function startRedisContainer(): Promise<RedisContainer> {
  const started = await runCommand('docker', [
    'run',
    '--detach',
    '--rm',
    '--publish',
    '127.0.0.1::6379',
    REDIS_IMAGE,
    'timeout',
    String(CONTAINER_LIFETIME_SECONDS),
    'redis-server',
  ])
  const containerId = started.stdout.trim()
  const stop = async () => {
    await runCommand('docker', ['rm', '--force', containerId])
  }
  try {
    const published = await runCommand('docker', ['port', containerId, '6379/tcp'])
    return { url: `redis://${published.stdout.trim()}`, stop }
  } catch (error) {
    await stop()
    throw error
  }
}
