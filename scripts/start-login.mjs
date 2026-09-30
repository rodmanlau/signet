import { spawn } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { applyLoginEnv } from './login-env.mjs'

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const dir = resolve(process.argv[2] ?? join(repoRoot, '.valar', 'login'))
const envPath = join(dir, 'login.env')

let text
try {
  text = await readFile(envPath, 'utf8')
} catch {
  process.stderr.write(`missing ${envPath}\nrun node scripts/setup-login.mjs first\n`)
  process.exit(1)
}

let env
try {
  env = applyLoginEnv(process.env, text, envPath)
} catch (error) {
  const message = error instanceof Error ? error.message : String(error)
  process.stderr.write(`${message}\n`)
  process.exit(1)
}

const child = spawn('npm', ['run', 'start', '-w', '@signet/server'], {
  cwd: repoRoot,
  env,
  stdio: 'inherit',
  shell: true,
})
child.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal)
  process.exit(code ?? 1)
})
