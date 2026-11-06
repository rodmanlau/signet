import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { keygenAsync as generateKeyPair } from '@noble/ed25519'
import { describe, expect, it } from 'vitest'
import { agentSubject } from '../src/identity.js'
import {
  grantsFilePath,
  isGranted,
  loadGrants,
  revokeGrant,
  upsertGrant,
  writeGrants,
  type AgentGrant,
  type GrantMap,
} from '../src/grants.js'

describe('agent grants', () => {
  it('loads an empty store when the file is missing and does not warn', async () => {
    const dir = await tempDir()
    try {
      const stderr = captureStderr()
      try {
        const store = await loadGrants(grantsFilePath(join(dir, 'sessions.json')))
        expect(store.size).toBe(0)
        expect(stderr.text()).toBe('')
      } finally {
        stderr.restore()
      }
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('loads an empty store and warns when the file is invalid', async () => {
    const dir = await tempDir()
    const file = grantsFilePath(join(dir, 'sessions.json'))
    try {
      await writeFile(file, '{', 'utf8')
      const stderr = captureStderr()
      try {
        const store = await loadGrants(file)
        expect(store.size).toBe(0)
        expect(stderr.text()).toBe(`invalid agent grants file ${file}; agent proofs stay unauthorized\n`)
      } finally {
        stderr.restore()
      }
      await writeFile(file, '{}', 'utf8')
      const again = captureStderr()
      try {
        expect((await loadGrants(file)).size).toBe(0)
        expect(again.text()).toContain('agent proofs stay unauthorized')
      } finally {
        again.restore()
      }
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('rejects a file that lists one public key twice', async () => {
    const dir = await tempDir()
    const file = grantsFilePath(join(dir, 'sessions.json'))
    const { publicKey } = await generateKeyPair()
    const record = {
      ownerProvider: 'google',
      ownerSubject: 'ada',
      publicKey: Buffer.from(publicKey).toString('base64url'),
      label: 'Cursor',
      createdAt: 1_700_000_000,
    }
    try {
      await writeFile(file, JSON.stringify([record, { ...record, ownerSubject: 'bea' }]), 'utf8')
      const stderr = captureStderr()
      try {
        expect((await loadGrants(file)).size).toBe(0)
        expect(stderr.text()).toContain('agent proofs stay unauthorized')
      } finally {
        stderr.restore()
      }
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('round-trips a grant as unpadded base64url records and keeps mode 0600', async () => {
    const dir = await tempDir()
    const file = grantsFilePath(join(dir, 'sessions.json'))
    const { publicKey } = await generateKeyPair()
    const grant = sample(publicKey, 'Cursor')
    try {
      const store: GrantMap = new Map()
      expect(upsertGrant(store, grant)).toBe(true)
      await writeGrants(file, store)
      expect((await stat(file)).mode & 0o777).toBe(0o600)
      const parsed = JSON.parse(await readFile(file, 'utf8')) as unknown
      const wireKey = Buffer.from(publicKey).toString('base64url')
      expect(wireKey).not.toContain('=')
      expect(parsed).toEqual([
        {
          ownerProvider: 'google',
          ownerSubject: 'owner-1',
          publicKey: wireKey,
          label: 'Cursor',
          createdAt: 1_700_000_000,
        },
      ])
      const loaded = await loadGrants(file)
      expect(isGranted(loaded, publicKey)).toBe(true)
      expect(loaded.get(agentSubject(publicKey))).toEqual(grant)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('updates the label for the same owner and refuses a different owner', async () => {
    const { publicKey } = await generateKeyPair()
    const store: GrantMap = new Map()
    const original = Uint8Array.from(publicKey)
    expect(upsertGrant(store, sample(original, 'Cursor'))).toBe(true)
    original[0] ^= 0xff
    expect(isGranted(store, publicKey)).toBe(true)
    expect(isGranted(store, original)).toBe(false)
    expect(upsertGrant(store, sample(publicKey, 'Cursor again', 1_800_000_000))).toBe(true)
    const saved = store.get(agentSubject(publicKey))
    expect(saved?.label).toBe('Cursor again')
    expect(saved?.createdAt).toBe(1_700_000_000)
    expect(
      upsertGrant(store, {
        ...sample(publicKey, 'stolen'),
        ownerProvider: 'apple',
        ownerSubject: 'someone-else',
      }),
    ).toBe(false)
    expect(store.get(agentSubject(publicKey))?.label).toBe('Cursor again')
    expect(store.get(agentSubject(publicKey))?.ownerProvider).toBe('google')
  })

  it('revokes only the owner of that public key', async () => {
    const { publicKey } = await generateKeyPair()
    const store: GrantMap = new Map()
    expect(upsertGrant(store, sample(publicKey, 'Cursor'))).toBe(true)
    expect(revokeGrant(store, 'apple', 'owner-1', publicKey)).toBe(false)
    expect(revokeGrant(store, 'google', 'other', publicKey)).toBe(false)
    expect(isGranted(store, publicKey)).toBe(true)
    expect(revokeGrant(store, 'google', 'owner-1', publicKey)).toBe(true)
    expect(isGranted(store, publicKey)).toBe(false)
    expect(revokeGrant(store, 'google', 'owner-1', publicKey)).toBe(false)
  })

  it('refuses a grant with a newline in the label', async () => {
    const { publicKey } = await generateKeyPair()
    const store: GrantMap = new Map()
    expect(upsertGrant(store, sample(publicKey, 'bad\nlabel'))).toBe(false)
    expect(store.size).toBe(0)
  })
})

function sample(publicKey: Uint8Array, label: string, createdAt = 1_700_000_000): AgentGrant {
  return {
    ownerProvider: 'google',
    ownerSubject: 'owner-1',
    publicKey,
    label,
    createdAt,
  }
}

async function tempDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'valar-grants-'))
}

function captureStderr(): { text(): string; restore(): void } {
  const chunks: string[] = []
  const write = process.stderr.write
  process.stderr.write = ((chunk: string | Uint8Array) => {
    chunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'))
    return true
  }) as typeof process.stderr.write
  return {
    text: () => chunks.join(''),
    restore() {
      process.stderr.write = write
    },
  }
}
