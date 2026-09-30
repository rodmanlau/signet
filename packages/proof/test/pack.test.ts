import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { expect, it } from 'vitest'

const execFileAsync = promisify(execFile)
const repoRoot = fileURLToPath(new URL('../../..', import.meta.url))

it('packs javascript, keeps the SHA-512 import, and has no install script', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'signet-pack-'))
  try {
    await execFileAsync('npm', ['run', 'build', '-w', '@signet/proof'], { cwd: repoRoot, shell: true })
    for (const name of ['verify.js', 'sign.js', 'agent.js']) {
      const source = await readFile(join(repoRoot, 'packages', 'proof', 'dist', name), 'utf8')
      expect(source).toContain("import './ed25519.js'")
    }
    const { stdout } = await execFileAsync(
      'npm',
      ['pack', '-w', '@signet/proof', '--pack-destination', dir, '--json'],
      { cwd: repoRoot, shell: true },
    )
    const packed = JSON.parse(stdout) as { filename: string; files: { path: string }[] }[]
    const filename = packed[0].filename
    expect(filename).toBe('signet-proof-0.1.0.tgz')
    const paths = packed[0].files.map((file) => file.path)
    expect(paths).toContain('dist/index.js')
    expect(paths).toContain('dist/ed25519.js')
    expect(paths.some((path) => path.startsWith('src/'))).toBe(false)
    const extracted = await execFileAsync('tar', ['-xOf', join(dir, filename), 'package/package.json'])
    const pkg = JSON.parse(extracted.stdout) as { version: string; scripts?: Record<string, string> }
    expect(pkg.version).toBe('0.1.0')
    for (const key of ['install', 'preinstall', 'postinstall', 'prepare']) {
      expect(pkg.scripts?.[key]).toBeUndefined()
    }
  } finally {
    await rm(dir, { recursive: true, force: true })
    await rm(join(repoRoot, 'packages', 'proof', 'dist'), { recursive: true, force: true })
  }
})

it('refuses to publish the server and the client', async () => {
  for (const name of ['@signet/server', '@signet/client']) {
    const result = await execFileAsync('npm', ['publish', '-w', name, '--dry-run'], {
      cwd: repoRoot,
      shell: true,
    }).then(
      () => ({ code: 0, stderr: '' }),
      (error: { code?: number; stderr?: string }) => ({ code: error.code ?? 1, stderr: error.stderr ?? '' }),
    )
    expect(result.code).not.toBe(0)
    expect(result.stderr.toLowerCase()).toContain('private')
  }
})
