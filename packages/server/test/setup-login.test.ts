import { execFile } from 'node:child_process'
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { expect, it } from 'vitest'

const execFileAsync = promisify(execFile)
const repoRoot = fileURLToPath(new URL('../../..', import.meta.url))

async function runSetup(dir: string): Promise<{ stdout: string; stderr: string; code: number }> {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, ['scripts/setup-login.mjs', dir], {
      cwd: repoRoot,
      encoding: 'utf8',
    })
    return { stdout, stderr, code: 0 }
  } catch (error) {
    const failed = error as { stdout?: string; stderr?: string; code?: number }
    return { stdout: failed.stdout ?? '', stderr: failed.stderr ?? '', code: failed.code ?? 1 }
  }
}

it('writes SIGNET_ names into a new login.env and keeps an existing file and both keys', async () => {
  const fresh = await mkdtemp(join(tmpdir(), 'signet-setup-'))
  const kept = await mkdtemp(join(tmpdir(), 'signet-setup-keep-'))
  const half = await mkdtemp(join(tmpdir(), 'signet-setup-half-'))
  try {
    const created = await runSetup(fresh)
    const envPath = join(fresh, 'login.env')
    const text = await readFile(envPath, 'utf8')
    expect(created.code).toBe(0)
    expect(created.stdout).toContain(`wrote ${envPath}`)
    expect(text).toContain(`SIGNET_SESSIONS=${join(fresh, 'sessions.json')}`)
    expect(text).toContain('SIGNET_PRIVATE_KEY=')
    expect(text).toContain('SIGNET_DERIVATION_KEY=')
    expect(text).toContain('SIGNET_KEY_ID=k1')
    expect(text).toContain('SIGNET_TEST=1')
    expect(text).not.toContain('SIGNET_HOST')
    expect(text).not.toContain('SIGNET_PORT')
    expect(text).not.toContain('SIGNET_ISSUER')
    expect(text).not.toContain('VALAR_')
    const privateBefore = await readFile(join(fresh, 'private-key'))
    const derivationBefore = await readFile(join(fresh, 'derivation-key'))
    const again = await runSetup(fresh)
    expect(again.code).toBe(0)
    expect(again.stdout).toContain('keeping existing keys')
    expect(again.stdout).toContain(`keeping ${envPath}`)
    expect(await readFile(envPath, 'utf8')).toBe(text)
    expect(Buffer.compare(await readFile(join(fresh, 'private-key')), privateBefore)).toBe(0)
    expect(Buffer.compare(await readFile(join(fresh, 'derivation-key')), derivationBefore)).toBe(0)

    const oldPath = join(kept, 'login.env')
    const oldText = 'VALAR_LOGIN_SESSIONS=keep-me\n'
    await writeFile(oldPath, oldText, 'utf8')
    const keptOut = await runSetup(kept)
    expect(keptOut.code).toBe(0)
    expect(keptOut.stdout).toContain(`keeping ${oldPath}`)
    expect(await readFile(oldPath, 'utf8')).toBe(oldText)

    await writeFile(join(half, 'private-key'), privateBefore)
    const refused = await runSetup(half)
    expect(refused.code).not.toBe(0)
    expect(refused.stderr).toContain('refusing to mint one key beside an existing key')
    expect(Buffer.compare(await readFile(join(half, 'private-key')), privateBefore)).toBe(0)
  } finally {
    await rm(fresh, { recursive: true, force: true })
    await rm(kept, { recursive: true, force: true })
    await rm(half, { recursive: true, force: true })
  }
})
