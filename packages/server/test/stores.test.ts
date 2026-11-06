import { mkdtemp, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  createWriteQueue,
  openJsonGrantStore,
  openJsonSessionStore,
} from '../src/stores.js'

const SESSION_ID = 'aaaaaaaaaaaaaaaa'

describe('json stores', () => {
  it('round-trips a session through the json file', async () => {
    const dir = await tempDir()
    const file = join(dir, 'sessions.json')
    const queue = createWriteQueue()
    const session = { provider: 'google' as const, subject: 'ada', label: 'Ada' }
    try {
      const store = await openJsonSessionStore(file, queue)
      expect(store.get(SESSION_ID)).toBeUndefined()
      store.set(SESSION_ID, session)
      await store.persist()
      expect((await stat(file)).mode & 0o777).toBe(0o600)
      const loaded = await openJsonSessionStore(file, queue)
      expect(loaded.get(SESSION_ID)).toEqual(session)
      expect(loaded.delete(SESSION_ID)).toEqual(session)
      expect(loaded.get(SESSION_ID)).toBeUndefined()
      await loaded.persist()
      const gone = await openJsonSessionStore(file, queue)
      expect(gone.get(SESSION_ID)).toBeUndefined()
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('throws when the session file is not a json object of sessions', async () => {
    const dir = await tempDir()
    const file = join(dir, 'sessions.json')
    const queue = createWriteQueue()
    try {
      await writeFile(file, '{', 'utf8')
      await expect(openJsonSessionStore(file, queue)).rejects.toThrow(
        /^SIGNET_SESSIONS must be a JSON object of sessions$/,
      )
      await writeFile(
        file,
        JSON.stringify({
          'aaaaaaaaaaaaaaa+': { provider: 'google', subject: 'ada', label: 'Ada' },
        }),
        'utf8',
      )
      await expect(openJsonSessionStore(file, queue)).rejects.toThrow(
        /^SIGNET_SESSIONS must be a JSON object of sessions$/,
      )
      await writeFile(
        file,
        JSON.stringify({
          [SESSION_ID]: { provider: 'nope', subject: 'ada', label: 'Ada' },
        }),
        'utf8',
      )
      await expect(openJsonSessionStore(file, queue)).rejects.toThrow(
        /^SIGNET_SESSIONS must be a JSON object of sessions$/,
      )
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('round-trips a grant through the json file', async () => {
    const dir = await tempDir()
    const file = join(dir, 'agent-grants.json')
    const queue = createWriteQueue()
    const publicKey = new Uint8Array(32)
    publicKey[0] = 7
    const grant = {
      ownerProvider: 'google' as const,
      ownerSubject: 'ada',
      publicKey,
      label: 'Cursor',
      createdAt: 1_700_000_000,
    }
    try {
      const store = await openJsonGrantStore(file, queue)
      expect(store.get(publicKey)).toBeUndefined()
      expect(store.upsert(grant)).toBe(true)
      await store.persist()
      const loaded = await openJsonGrantStore(file, queue)
      expect(loaded.isGranted(publicKey)).toBe(true)
      expect(loaded.get(publicKey)).toEqual(grant)
      expect(loaded.listForOwner('google', 'ada')).toEqual([grant])
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('opens a missing grants file as an empty store and does not warn', async () => {
    const dir = await tempDir()
    const file = join(dir, 'agent-grants.json')
    const stderr = captureStderr()
    try {
      const store = await openJsonGrantStore(file, createWriteQueue())
      expect(store.isGranted(new Uint8Array(32))).toBe(false)
      expect(store.listForOwner('google', 'ada')).toEqual([])
      expect(stderr.text()).toBe('')
    } finally {
      stderr.restore()
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('opens a corrupt grants file as an empty store and warns', async () => {
    const dir = await tempDir()
    const file = join(dir, 'agent-grants.json')
    await writeFile(file, '{', 'utf8')
    const stderr = captureStderr()
    try {
      const store = await openJsonGrantStore(file, createWriteQueue())
      expect(store.isGranted(new Uint8Array(32))).toBe(false)
      expect(store.listForOwner('google', 'ada')).toEqual([])
      expect(stderr.text()).toBe(`invalid agent grants file ${file}; agent proofs stay unauthorized\n`)
    } finally {
      stderr.restore()
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('runs queued tasks in order and continues after a rejection', async () => {
    const queue = createWriteQueue()
    const order: string[] = []
    const first = queue.run(async () => {
      order.push('first')
      throw new Error('disk')
    })
    const second = queue.run(async () => {
      order.push('second')
    })
    await expect(first).rejects.toThrow('disk')
    await second
    expect(order).toEqual(['first', 'second'])
  })
})

async function tempDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'valar-stores-'))
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
