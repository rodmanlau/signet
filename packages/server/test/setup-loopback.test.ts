import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { expect, it } from 'vitest'

const execFileAsync = promisify(execFile)
const repoRoot = fileURLToPath(new URL('../../..', import.meta.url))

async function runSetup(dir: string): Promise<{ stdout: string; stderr: string; code: number }> {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, ['scripts/setup-loopback.mjs', dir], {
      cwd: repoRoot,
      encoding: 'utf8',
    })
    return { stdout, stderr, code: 0 }
  } catch (error) {
    const failed = error as { stdout?: string; stderr?: string; code?: number }
    return { stdout: failed.stdout ?? '', stderr: failed.stderr ?? '', code: failed.code ?? 1 }
  }
}

it('writes loopback key names and keeps an existing file and both keys', async () => {
  const fresh = await mkdtemp(join(tmpdir(), 'signet-loopback-setup-'))
  const half = await mkdtemp(join(tmpdir(), 'signet-loopback-half-'))
  try {
    const created = await runSetup(fresh)
    const envPath = join(fresh, 'login.env')
    const text = await readFile(envPath, 'utf8')
    expect(created.code).toBe(0)
    expect(created.stdout).toContain(`wrote ${envPath}`)
    expect(created.stdout).toContain(`public keys for the loopback issuer: ${join(fresh, 'identity-keys.json')}`)
    expect(text).toContain('SIGNET_LOOPBACK_PRIVATE_KEY=')
    expect(text).toContain('SIGNET_LOOPBACK_DERIVATION_KEY=')
    expect(text).toContain('SIGNET_LOOPBACK_KEY_ID=k1')
    expect(text).not.toContain('SIGNET_PRIVATE_KEY')
    expect(text).not.toContain('SIGNET_DERIVATION_KEY')
    expect(text).not.toContain('SIGNET_TEST')
    expect(text).not.toContain('SIGNET_HOST')
    expect(text).not.toContain('SIGNET_PORT')
    expect(text).not.toContain('SIGNET_ISSUER')
    expect(text).not.toContain('SIGNET_SESSIONS')
    const keys = JSON.parse(await readFile(join(fresh, 'identity-keys.json'), 'utf8')) as {
      id: string
      publicKey: string
    }[]
    expect(keys).toHaveLength(1)
    expect(keys[0]?.id).toBe('k1')
    const privateBefore = await readFile(join(fresh, 'private-key'))
    const derivationBefore = await readFile(join(fresh, 'derivation-key'))
    expect(privateBefore).toHaveLength(32)
    expect(derivationBefore).toHaveLength(32)
    expect(Buffer.compare(privateBefore, derivationBefore)).not.toBe(0)

    const again = await runSetup(fresh)
    expect(again.code).toBe(0)
    expect(again.stdout).toContain('keeping existing keys')
    expect(again.stdout).toContain(`keeping ${envPath}`)
    expect(await readFile(envPath, 'utf8')).toBe(text)
    expect(Buffer.compare(await readFile(join(fresh, 'private-key')), privateBefore)).toBe(0)
    expect(Buffer.compare(await readFile(join(fresh, 'derivation-key')), derivationBefore)).toBe(0)

    await writeFile(join(half, 'private-key'), privateBefore)
    const refused = await runSetup(half)
    expect(refused.code).not.toBe(0)
    expect(refused.stderr).toContain('refusing to mint one key beside an existing key')
  } finally {
    await rm(fresh, { recursive: true, force: true })
    await rm(half, { recursive: true, force: true })
  }
})
