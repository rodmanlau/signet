import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import type { Pool } from 'pg'
import { createPgPool } from '../src/pg-store.js'

const repoRoot = fileURLToPath(new URL('../../..', import.meta.url))
const schema = 'pg3_import'
const baseUrl = (process.env.DATABASE_URL ?? '').trim()
const databaseUrl = baseUrl === '' ? '' : withSearchPath(baseUrl, schema)
let pool: Pool

type RunResult = { stdout: string; stderr: string; code: number }

const keyA = Buffer.alloc(32, 1).toString('base64url')
const keyB = Buffer.alloc(32, 2).toString('base64url')

function withSearchPath(url: string, schemaName: string): string {
  const parsed = new URL(url)
  parsed.searchParams.set('options', `-csearch_path=${schemaName}`)
  return parsed.toString()
}

function runImport(args: string[], env: NodeJS.ProcessEnv): Promise<RunResult> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [join(repoRoot, 'scripts/import-json-to-postgres.mjs'), ...args],
      { cwd: repoRoot, encoding: 'utf8', env },
      (error, stdout, stderr) => {
        const failed = error as NodeJS.ErrnoException | null
        resolve({
          stdout: stdout ?? '',
          stderr: stderr ?? '',
          code: failed ? (failed.code ?? 1) : 0,
        })
      },
    )
  })
}

function childEnv(url: string | undefined): NodeJS.ProcessEnv {
  const env = { ...process.env }
  if (url === undefined) delete env.DATABASE_URL
  else env.DATABASE_URL = url
  return env
}

describe('import json boundaries', () => {
  it('exits non-zero when DATABASE_URL is missing', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'signet-import-'))
    try {
      const sessions = join(dir, 'sessions.json')
      await writeFile(sessions, '{}\n')
      const result = await runImport(['--sessions', sessions], childEnv(undefined))
      expect(result.code).not.toBe(0)
      expect(result.stderr).toContain('DATABASE_URL is required')
      expect(result.stdout).toBe('')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('exits non-zero when the sessions file is missing', async () => {
    const missing = join(tmpdir(), 'signet-import-missing', 'sessions.json')
    const result = await runImport(['--sessions', missing], childEnv('postgres://signet:signet@127.0.0.1:1/signet'))
    expect(result.code).not.toBe(0)
    expect(result.stderr).toContain('sessions file not found')
    expect(result.stdout).toBe('')
  })

  it('exits non-zero when the sessions file or the grants file is corrupt', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'signet-import-'))
    const env = childEnv('postgres://signet:signet@127.0.0.1:1/signet')
    try {
      const sessions = join(dir, 'sessions.json')
      const grants = join(dir, 'agent-grants.json')
      await writeFile(sessions, '[\n')
      const badSessions = await runImport(['--sessions', sessions], env)
      expect(badSessions.code).not.toBe(0)
      expect(badSessions.stderr).toContain(`invalid sessions file ${sessions}`)

      await writeFile(sessions, '{}\n')
      await writeFile(grants, '{')
      const badGrants = await runImport(['--sessions', sessions, '--grants', grants], env)
      expect(badGrants.code).not.toBe(0)
      expect(badGrants.stderr).toContain(`invalid agent grants file ${grants}`)

      const shortId = 'a'.repeat(15)
      await writeFile(sessions, JSON.stringify({ [shortId]: { provider: 'google', subject: 'ada', label: 'Ada' } }))
      const short = await runImport(['--sessions', sessions], env)
      expect(short.code).not.toBe(0)
      expect(short.stderr).toContain(`invalid sessions file ${sessions}`)

      const longSubject = 's'.repeat(513)
      await writeFile(
        sessions,
        JSON.stringify({ ['a'.repeat(16)]: { provider: 'google', subject: longSubject, label: 'Ada' } }),
      )
      const long = await runImport(['--sessions', sessions], env)
      expect(long.code).not.toBe(0)
      expect(long.stderr).toContain(`invalid sessions file ${sessions}`)

      await writeFile(
        grants,
        JSON.stringify([
          { ownerProvider: 'google', ownerSubject: 'ada', publicKey: keyA, label: 'Cursor', createdAt: 1 },
          { ownerProvider: 'apple', ownerSubject: 'bea', publicKey: keyA, label: 'Cursor', createdAt: 2 },
        ]),
      )
      await writeFile(sessions, '{}\n')
      const duplicate = await runImport(['--sessions', sessions, '--grants', grants], env)
      expect(duplicate.code).not.toBe(0)
      expect(duplicate.stderr).toContain(`invalid agent grants file ${grants}`)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})

describe.skipIf(!process.env.DATABASE_URL)('import json into postgres', () => {
  beforeAll(async () => {
    const admin = createPgPool(baseUrl)
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`)
    await admin.query(`CREATE SCHEMA ${schema}`)
    await admin.end()
    pool = createPgPool(databaseUrl)
    const current = await pool.query<{ schema: string }>('SELECT current_schema() AS schema')
    if (current.rows[0]?.schema !== schema) {
      throw new Error(`expected search_path ${schema}, got ${current.rows[0]?.schema ?? 'none'}`)
    }
  })

  afterAll(async () => {
    await pool?.end()
    const admin = createPgPool(baseUrl)
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`)
    await admin.end()
  })

  beforeEach(async () => {
    const found = await pool.query(`SELECT to_regclass('${schema}.sessions') AS sessions, to_regclass('${schema}.agent_grants') AS grants`)
    if (found.rows[0]?.sessions && found.rows[0]?.grants) {
      await pool.query(`TRUNCATE ${schema}.sessions, ${schema}.agent_grants`)
    }
  })

  it('imports an empty session file when the grants file is missing', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'signet-import-'))
    try {
      const sessions = join(dir, 'sessions.json')
      await writeFile(sessions, '{}\n')
      const result = await runImport(['--sessions', sessions, '--check'], childEnv(databaseUrl))
      expect(result.code).toBe(0)
      expect(result.stdout).toBe('sessions=0 grants=0\n')
      expect(await counts()).toEqual({ sessions: 0, grants: 0 })
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('imports two sessions and two grants, passes --check, and keeps the same counts on a second run', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'signet-import-'))
    try {
      const files = await writeFixture(dir, 'Ada', 'Cursor')
      const first = await runImport(['--sessions', files.sessions, '--grants', files.grants, '--check'], childEnv(databaseUrl))
      expect(first.code).toBe(0)
      expect(first.stdout).toBe('sessions=2 grants=2\n')
      expect(first.stderr).toBe('')
      expect(await sessionRows()).toEqual([
        { id: 'aaaaaaaaaaaaaaaa', provider: 'google', subject: 'ada', label: 'Ada' },
        { id: 'bbbbbbbbbbbbbbbb', provider: 'apple', subject: 'bea', label: 'Bea' },
      ])
      expect(await grantRows()).toEqual([
        { publicKey: keyA, ownerProvider: 'google', ownerSubject: 'ada', label: 'Cursor', createdAt: 1_700_000_000 },
        { publicKey: keyB, ownerProvider: 'apple', ownerSubject: 'bea', label: 'Nightly', createdAt: 1_700_000_001 },
      ])

      const second = await runImport(
        ['--sessions', files.sessions, '--grants', files.grants, '--check'],
        childEnv(databaseUrl),
      )
      expect(second.code).toBe(0)
      expect(second.stdout).toBe('sessions=2 grants=2\n')
      expect(await counts()).toEqual({ sessions: 2, grants: 2 })
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('replaces labels when the same ids are imported again', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'signet-import-'))
    try {
      const files = await writeFixture(dir, 'Ada', 'Cursor')
      expect((await runImport(['--sessions', files.sessions, '--grants', files.grants], childEnv(databaseUrl))).code).toBe(0)
      await writeFixture(dir, 'Ada Lovelace', 'Cursor nightly')
      const updated = await runImport(['--sessions', files.sessions, '--grants', files.grants, '--check'], childEnv(databaseUrl))
      expect(updated.code).toBe(0)
      expect(updated.stdout).toBe('sessions=2 grants=2\n')
      const sessions = await sessionRows()
      expect(sessions.find((row) => row.id === 'aaaaaaaaaaaaaaaa')?.label).toBe('Ada Lovelace')
      const grants = await grantRows()
      expect(grants.find((row) => row.publicKey === keyA)?.label).toBe('Cursor nightly')
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('exits non-zero and keeps the existing owner when a grant would move', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'signet-import-'))
    try {
      const sessions = join(dir, 'sessions.json')
      const grants = join(dir, 'agent-grants.json')
      await writeFile(sessions, '{}\n')
      await writeFile(
        grants,
        JSON.stringify([
          { ownerProvider: 'google', ownerSubject: 'ada', publicKey: keyA, label: 'Cursor', createdAt: 10 },
        ]),
      )
      expect((await runImport(['--sessions', sessions, '--grants', grants], childEnv(databaseUrl))).code).toBe(0)
      await writeFile(
        grants,
        JSON.stringify([
          { ownerProvider: 'google', ownerSubject: 'ada', publicKey: keyB, label: 'Other', createdAt: 11 },
          { ownerProvider: 'apple', ownerSubject: 'bea', publicKey: keyA, label: 'Stolen', createdAt: 12 },
        ]),
      )
      const stolen = await runImport(['--sessions', sessions, '--grants', grants, '--check'], childEnv(databaseUrl))
      expect(stolen.code).not.toBe(0)
      expect(stolen.stderr).toContain(`agent grant ${keyA} belongs to google ada`)
      expect(stolen.stderr).toContain('Refusing to replace it with apple bea')
      expect(await grantRows()).toEqual([
        { publicKey: keyA, ownerProvider: 'google', ownerSubject: 'ada', label: 'Cursor', createdAt: 10 },
      ])
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('exits non-zero when --check sees rows that are not in the files', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'signet-import-'))
    try {
      const files = await writeFixture(dir, 'Ada', 'Cursor')
      expect(
        (await runImport(['--sessions', files.sessions, '--grants', files.grants], childEnv(databaseUrl))).code,
      ).toBe(0)
      await pool.query(
        `INSERT INTO ${schema}.sessions (id, provider, subject, label) VALUES ($1, $2, $3, $4)`,
        ['cccccccccccccccc', 'facebook', 'cy', 'Cy'],
      )
      const checked = await runImport(
        ['--sessions', files.sessions, '--grants', files.grants, '--check'],
        childEnv(databaseUrl),
      )
      expect(checked.code).not.toBe(0)
      expect(checked.stdout).toBe('sessions=3 grants=2\n')
      expect(checked.stderr).toContain('count mismatch')
      expect(await counts()).toEqual({ sessions: 3, grants: 2 })
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})

async function writeFixture(
  dir: string,
  adaLabel: string,
  cursorLabel: string,
): Promise<{ sessions: string; grants: string }> {
  const sessions = join(dir, 'sessions.json')
  const grants = join(dir, 'agent-grants.json')
  await writeFile(
    sessions,
    JSON.stringify({
      ['aaaaaaaaaaaaaaaa']: { provider: 'google', subject: 'ada', label: adaLabel },
      ['bbbbbbbbbbbbbbbb']: { provider: 'apple', subject: 'bea', label: 'Bea' },
    }),
  )
  await writeFile(
    grants,
    JSON.stringify([
      { ownerProvider: 'google', ownerSubject: 'ada', publicKey: keyA, label: cursorLabel, createdAt: 1_700_000_000 },
      { ownerProvider: 'apple', ownerSubject: 'bea', publicKey: keyB, label: 'Nightly', createdAt: 1_700_000_001 },
    ]),
  )
  return { sessions, grants }
}

async function counts(): Promise<{ sessions: number; grants: number }> {
  const sessions = await poolCount('sessions')
  const grants = await poolCount('agent_grants')
  return { sessions, grants }
}

async function poolCount(table: 'sessions' | 'agent_grants'): Promise<number> {
  const result = await pool.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${schema}.${table}`)
  return Number(result.rows[0].n)
}

async function sessionRows(): Promise<Array<{ id: string; provider: string; subject: string; label: string }>> {
  const result = await pool.query<{ id: string; provider: string; subject: string; label: string }>(
    `SELECT id, provider, subject, label FROM ${schema}.sessions ORDER BY id`,
  )
  return result.rows
}

async function grantRows(): Promise<
  Array<{ publicKey: string; ownerProvider: string; ownerSubject: string; label: string; createdAt: number }>
> {
  const result = await pool.query<{
    public_key: Buffer
    owner_provider: string
    owner_subject: string
    label: string
    created_at: string | number
  }>(`SELECT public_key, owner_provider, owner_subject, label, created_at FROM ${schema}.agent_grants ORDER BY created_at`)
  return result.rows.map((row) => ({
    publicKey: Buffer.from(row.public_key).toString('base64url'),
    ownerProvider: row.owner_provider,
    ownerSubject: row.owner_subject,
    label: row.label,
    createdAt: Number(row.created_at),
  }))
}
