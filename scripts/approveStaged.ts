import { execFileSync } from 'node:child_process'

function run(command: string, args: string[]): void {
  execFileSync(command, args, { stdio: 'inherit' })
}

// Ctrl-C then only stops the running command, so the logout below still runs.
process.on('SIGINT', () => {})

run('npm', ['login'])
try {
  run('pnpm', ['stage', 'approve'])
} finally {
  run('npm', ['logout'])
}
