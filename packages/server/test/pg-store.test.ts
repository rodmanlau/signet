import { createServer } from 'node:http'
import { mkdtemp, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { keygenAsync as generateKeyPair } from '@noble/ed25519'
import { signAgentRequest, verifyProof } from '@agenticage/proof'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import type { Pool } from 'pg'
import { agentSubject, deriveIdentity } from '../src/identity.js'
import { startLogin } from '../src/main.js'
import { applyMigrations, createPgPool, openPgGrantStore, openPgSessionStore } from '../src/pg-store.js'
import { createWriteQueue } from '../src/stores.js'

const SESSION_ID = 'aaaaaaaaaaaaaaaa'
const ISSUER = 'https://login.example'
const AUDIENCE = 'http://127.0.0.1:8080'
const NOW = 1_700_000_000
const DERIVATION_KEY = new TextEncoder().encode('test-key')
const databaseUrl = (process.env.DATABASE_URL ?? '').trim()

describe('postgres startup', () => {
  it('rejects a bad DATABASE_URL before it listens', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const port = await freePort()
    await expect(
      startLogin({
        port,
        host: '127.0.0.1',
        issuer: ISSUER,
        keyId: 'k1',
        privateKey: secretKey,
        publicKey,
        derivationKey: DERIVATION_KEY,
        databaseUrl: 'postgres://signet:signet@127.0.0.1:1/signet',
      }),
    ).rejects.toThrow(/DATABASE_URL failed/)
    const probe = createServer()
    await listen(probe, port)
    await closeServer(probe)
  })
})

describe.skipIf(!process.env.DATABASE_URL)('postgres session and grant stores', () => {
  let pool: Pool

  beforeAll(async () => {
    pool = createPgPool(databaseUrl)
    await applyMigrations(pool)
  })

  afterAll(async () => {
    await pool.query('DELETE FROM agent_grants')
    await pool.query('DELETE FROM sessions')
    await pool.end()
  })

  beforeEach(async () => {
    await pool.query('DELETE FROM agent_grants')
    await pool.query('DELETE FROM sessions')
  })

  it('creates the session and grant tables', async () => {
    await pool.query('DROP TABLE IF EXISTS agent_grants')
    await pool.query('DROP TABLE IF EXISTS sessions')
    await applyMigrations(pool)
    await applyMigrations(pool)
    const tables = await pool.query<{ table_name: string }>(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema = 'public' AND table_name IN ('sessions', 'agent_grants')
       ORDER BY table_name`,
    )
    expect(tables.rows.map((row) => row.table_name)).toEqual(['agent_grants', 'sessions'])
    const index = await pool.query<{ indexname: string }>(
      "SELECT indexname FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'agent_grants_owner_idx'",
    )
    expect(index.rows.map((row) => row.indexname)).toEqual(['agent_grants_owner_idx'])
  })

  it('round-trips a session across a reopen', async () => {
    const queue = createWriteQueue()
    const session = { provider: 'google' as const, subject: 'ada', label: 'Ada' }
    const store = await openPgSessionStore(pool, queue)
    expect(store.get(SESSION_ID)).toBeUndefined()
    store.set(SESSION_ID, session)
    await store.persist()
    const loaded = await openPgSessionStore(pool, queue)
    expect(loaded.get(SESSION_ID)).toEqual(session)
    expect(loaded.delete(SESSION_ID)).toEqual(session)
    expect(loaded.get(SESSION_ID)).toBeUndefined()
    await loaded.persist()
    const gone = await openPgSessionStore(pool, queue)
    expect(gone.get(SESSION_ID)).toBeUndefined()
  })

  it('upserts, lists, and revokes a grant', async () => {
    const queue = createWriteQueue()
    const publicKey = new Uint8Array(32)
    publicKey[0] = 7
    const grant = {
      ownerProvider: 'google' as const,
      ownerSubject: 'ada',
      publicKey,
      label: 'Cursor',
      createdAt: NOW,
    }
    const store = await openPgGrantStore(pool, queue)
    expect(store.get(publicKey)).toBeUndefined()
    expect(store.upsert(grant)).toBe(true)
    expect(store.upsert({ ...grant, label: 'Cursor nightly' })).toBe(true)
    expect(store.listForOwner('google', 'ada')).toEqual([{ ...grant, label: 'Cursor nightly' }])
    await store.persist()
    const loaded = await openPgGrantStore(pool, queue)
    expect(loaded.isGranted(publicKey)).toBe(true)
    expect(loaded.get(publicKey)).toEqual({ ...grant, label: 'Cursor nightly' })
    expect(loaded.listForOwner('google', 'ada')).toEqual([{ ...grant, label: 'Cursor nightly' }])
    expect(loaded.listForOwner('apple', 'ada')).toEqual([])
    expect(loaded.revoke('apple', 'bea', publicKey)).toBe(false)
    expect(loaded.isGranted(publicKey)).toBe(true)
    expect(loaded.revoke('google', 'ada', publicKey)).toBe(true)
    expect(loaded.isGranted(publicKey)).toBe(false)
    await loaded.persist()
    const gone = await openPgGrantStore(pool, queue)
    expect(gone.isGranted(publicKey)).toBe(false)
    expect(gone.get(publicKey)).toBeUndefined()
    expect(gone.listForOwner('google', 'ada')).toEqual([])
  })

  it('refuses a second owner who takes the same public key', async () => {
    const queue = createWriteQueue()
    const publicKey = new Uint8Array(32)
    publicKey[0] = 9
    const grant = {
      ownerProvider: 'google' as const,
      ownerSubject: 'ada',
      publicKey,
      label: 'Cursor',
      createdAt: NOW,
    }
    const store = await openPgGrantStore(pool, queue)
    expect(store.upsert(grant)).toBe(true)
    expect(
      store.upsert({
        ownerProvider: 'apple',
        ownerSubject: 'bea',
        publicKey,
        label: 'Stolen',
        createdAt: NOW + 1,
      }),
    ).toBe(false)
    expect(store.get(publicKey)).toEqual(grant)
    await store.persist()
    const loaded = await openPgGrantStore(pool, queue)
    expect(loaded.get(publicKey)).toEqual(grant)
    expect(loaded.listForOwner('apple', 'bea')).toEqual([])
  })

  it('keeps sessions and grants after the pool restarts', async () => {
    const session = { provider: 'apple' as const, subject: 'bea', label: 'Bea' }
    const publicKey = new Uint8Array(32)
    publicKey[0] = 3
    const grant = {
      ownerProvider: 'apple' as const,
      ownerSubject: 'bea',
      publicKey,
      label: 'Cursor',
      createdAt: NOW,
    }
    const first = createPgPool(databaseUrl)
    try {
      const queue = createWriteQueue()
      const sessions = await openPgSessionStore(first, queue)
      sessions.set(SESSION_ID, session)
      await sessions.persist()
      const grants = await openPgGrantStore(first, queue)
      expect(grants.upsert(grant)).toBe(true)
      await grants.persist()
    } finally {
      await first.end()
    }
    const second = createPgPool(databaseUrl)
    try {
      const queue = createWriteQueue()
      const sessions = await openPgSessionStore(second, queue)
      expect(sessions.get(SESSION_ID)).toEqual(session)
      const grants = await openPgGrantStore(second, queue)
      expect(grants.isGranted(publicKey)).toBe(true)
      expect(grants.get(publicKey)).toEqual(grant)
    } finally {
      await second.end()
    }
  })

  it('allows an agent and returns a proof without writing json files', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const agent = await generateKeyPair()
    const dir = await mkdtemp(join(tmpdir(), 'signet-pg-login-'))
    const server = await startLogin({
      port: 0,
      host: '127.0.0.1',
      issuer: ISSUER,
      keyId: 'k1',
      privateKey: secretKey,
      publicKey,
      derivationKey: DERIVATION_KEY,
      now: () => NOW,
      testLogin: true,
      databaseUrl,
      sessionsFile: join(dir, 'sessions.json'),
    })
    try {
      const denied = await postAgentProof(server.url, agent.secretKey)
      expect(denied.status).toBe(403)
      const cookie = await signIn(server.url)
      const ticket = await issueTicket(server.url, agent.secretKey, 'Cursor')
      const approved = await fetch(new URL(approvePath(ticket), server.url), { method: 'POST', headers: { cookie } })
      expect(approved.status).toBe(200)
      const proof = await postAgentProof(server.url, agent.secretKey)
      expect(proof.status).toBe(200)
      const parsed = (await proof.json()) as { proof: string }
      expect(
        verifyProof(Buffer.from(parsed.proof, 'base64url'), {
          issuer: ISSUER,
          audience: AUDIENCE,
          keys: [{ id: 'k1', publicKey }],
          nowSeconds: NOW,
        }),
      ).toBe(deriveIdentity('agent', agentSubject(agent.publicKey), '127.0.0.1', DERIVATION_KEY))
      expect(await readdir(dir)).toEqual([])
    } finally {
      await server.close()
      await rm(dir, { recursive: true, force: true })
    }
  })
})

function listen(server: ReturnType<typeof createServer>, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, '127.0.0.1', () => {
      server.off('error', reject)
      resolve()
    })
  })
}

function closeServer(server: ReturnType<typeof createServer>): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()))
  })
}

async function freePort(): Promise<number> {
  const server = createServer()
  await listen(server, 0)
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('expected a tcp port')
  await closeServer(server)
  return address.port
}

function signedBody(secretKey: Uint8Array, extra: { label?: string }): Record<string, unknown> {
  const signed = signAgentRequest(AUDIENCE, secretKey, NOW)
  const body: Record<string, unknown> = {
    audience: AUDIENCE,
    publicKey: Buffer.from(signed.publicKey).toString('base64url'),
    issuedAt: NOW,
    signature: Buffer.from(signed.signature).toString('base64url'),
  }
  if (extra.label !== undefined) body.label = extra.label
  return body
}

function postAgentProof(origin: string, secretKey: Uint8Array): Promise<Response> {
  return fetch(new URL('/agent-proof', origin), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(signedBody(secretKey, {})),
  })
}

async function issueTicket(origin: string, secretKey: Uint8Array, label: string): Promise<string> {
  const res = await fetch(new URL('/agents/ticket', origin), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(signedBody(secretKey, { label })),
  })
  expect(res.status).toBe(200)
  const body = (await res.json()) as { ticket: string }
  return body.ticket
}

function approvePath(ticket: string): string {
  return `/agents/approve?ticket=${encodeURIComponent(ticket)}`
}

async function signIn(origin: string): Promise<string> {
  const res = await fetch(new URL('/test-login', origin), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ provider: 'google', subject: 'ada', label: 'Ada' }),
  })
  expect(res.status).toBe(204)
  const line = res.headers.getSetCookie().find((item) => item.startsWith('valar_session='))
  expect(line).toBeTruthy()
  const value = line?.slice(line.indexOf('=') + 1).split(';')[0] ?? ''
  return `valar_session=${value}`
}
