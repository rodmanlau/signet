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

it('rebuilds proof after the tests and before publish', async () => {
  const workflow = await readFile(join(repoRoot, '.github', 'workflows', 'publish-proof.yml'), 'utf8')
  const testAt = workflow.indexOf('npm test')
  const buildAt = workflow.indexOf('npm run build -w @signet/proof')
  const publishAt = workflow.indexOf('npm publish -w @signet/proof --access public')
  expect(testAt).toBeGreaterThanOrEqual(0)
  expect(buildAt).toBeGreaterThan(testAt)
  expect(publishAt).toBeGreaterThan(buildAt)
})

it('refuses to publish the server and the client', async () => {
  for (const name of ['@signet/server', '@signet/client']) {
    const result = await execFileAsync('npm', ['publish', '-w', name, '--dry-run', '--json'], {
      cwd: repoRoot,
      shell: true,
    }).then(
      (ok) => ({ stdout: ok.stdout, stderr: ok.stderr }),
      (error: { stdout?: string; stderr?: string }) => ({
        stdout: error.stdout ?? '',
        stderr: error.stderr ?? '',
      }),
    )
    const output = `${result.stdout}${result.stderr}`.toLowerCase()
    expect(output).toContain('private')
    expect(output).not.toContain('.tgz')
  }
})
