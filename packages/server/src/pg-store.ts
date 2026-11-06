import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Pool, type PoolClient } from 'pg'
import type { LoginSession } from './connect.js'
import {
  isGranted as mapIsGranted,
  listForOwner as mapListForOwner,
  revokeGrant,
  upsertGrant,
  type AgentGrant,
  type GrantMap,
} from './grants.js'
import { agentSubject, type ProviderName } from './identity.js'
import {
  createWriteQueue,
  isLoginSession,
  type GrantStore,
  type SessionStore,
  type WriteQueue,
} from './stores.js'

const MIGRATION_FILE = join(
  dirname(fileURLToPath(import.meta.url)),
  '../migrations/001_sessions_and_grants.sql',
)
const INVALID_SESSION_ROW = 'invalid session row'
const INVALID_GRANT_ROW = 'invalid agent grant row'

type SessionRow = { id: string; provider: string; subject: string; label: string }
type GrantRow = {
  public_key: unknown
  owner_provider: string
  owner_subject: string
  label: string
  created_at: unknown
}

export function createPgPool(databaseUrl: string): Pool {
  const pool = new Pool({
    connectionString: databaseUrl,
    max: 10,
    idleTimeoutMillis: 300_000,
    maxLifetimeSeconds: 600,
  })
  // Idle clients emit when Postgres restarts; without a listener the process exits.
  pool.on('error', (error) => {
    process.stderr.write(`postgres pool error: ${error.message}\n`)
  })
  return pool
}

export async function applyMigrations(pool: Pool): Promise<void> {
  const sql = await readFile(MIGRATION_FILE, 'utf8')
  await pool.query(sql)
}

export async function openPgSessionStore(pool: Pool, queue: WriteQueue): Promise<SessionStore> {
  try {
    await applyMigrations(pool)
    const sessions = await loadSessions(pool)
    return {
      get(id) {
        return sessions.get(id)
      },
      set(id, session) {
        sessions.set(id, session)
      },
      delete(id) {
        const session = sessions.get(id)
        if (session === undefined) return undefined
        sessions.delete(id)
        return session
      },
      persist() {
        return queue.run(() => writeSessions(pool, sessions))
      },
    }
  } catch (error) {
    throw asDatabaseUrlError(error)
  }
}

export async function openPgGrantStore(pool: Pool, queue: WriteQueue): Promise<GrantStore> {
  try {
    await applyMigrations(pool)
    const grants = await loadGrantMap(pool)
    return {
      get(publicKey) {
        if (publicKey.length !== 32) return undefined
        return grants.get(agentSubject(publicKey))
      },
      isGranted(publicKey) {
        return mapIsGranted(grants, publicKey)
      },
      upsert(grant) {
        return upsertGrant(grants, grant)
      },
      revoke(ownerProvider, ownerSubject, publicKey) {
        return revokeGrant(grants, ownerProvider, ownerSubject, publicKey)
      },
      listForOwner(ownerProvider, ownerSubject) {
        return mapListForOwner(grants, ownerProvider, ownerSubject)
      },
      persist() {
        return queue.run(() => writeGrantMap(pool, grants))
      },
    }
  } catch (error) {
    throw asDatabaseUrlError(error)
  }
}

export async function connectDatabase(databaseUrl: string): Promise<{
  pool: Pool
  sessions: SessionStore
  grants: GrantStore
  close(): Promise<void>
}> {
  const pool = createPgPool(databaseUrl)
  const queue = createWriteQueue()
  try {
    const sessions = await openPgSessionStore(pool, queue)
    const grants = await openPgGrantStore(pool, queue)
    return { pool, sessions, grants, close: () => pool.end() }
  } catch (error) {
    await pool.end().catch(() => undefined)
    throw asDatabaseUrlError(error)
  }
}

async function loadSessions(pool: Pool): Promise<Map<string, LoginSession>> {
  const result = await pool.query<SessionRow>('SELECT id, provider, subject, label FROM sessions')
  const sessions = new Map<string, LoginSession>()
  for (const row of result.rows) {
    const session = { provider: row.provider, subject: row.subject, label: row.label }
    if (typeof row.id !== 'string' || row.id.length === 0 || !isLoginSession(session)) {
      throw new Error(INVALID_SESSION_ROW)
    }
    sessions.set(row.id, session)
  }
  return sessions
}

async function loadGrantMap(pool: Pool): Promise<GrantMap> {
  const result = await pool.query<GrantRow>(
    'SELECT public_key, owner_provider, owner_subject, label, created_at FROM agent_grants ORDER BY created_at, public_key',
  )
  const grants: GrantMap = new Map()
  for (const row of result.rows) {
    const grant = grantFromRow(row)
    if (!grant || !upsertGrant(grants, grant)) throw new Error(INVALID_GRANT_ROW)
  }
  return grants
}

async function writeSessions(pool: Pool, sessions: Map<string, LoginSession>): Promise<void> {
  await withTransaction(pool, async (client) => {
    await client.query('DELETE FROM sessions')
    for (const [id, session] of sessions) {
      await client.query('INSERT INTO sessions (id, provider, subject, label) VALUES ($1, $2, $3, $4)', [
        id,
        session.provider,
        session.subject,
        session.label,
      ])
    }
  })
}

async function writeGrantMap(pool: Pool, grants: GrantMap): Promise<void> {
  await withTransaction(pool, async (client) => {
    await client.query('DELETE FROM agent_grants')
    for (const grant of grants.values()) {
      await client.query(
        'INSERT INTO agent_grants (public_key, owner_provider, owner_subject, label, created_at) VALUES ($1, $2, $3, $4, $5)',
        [Buffer.from(grant.publicKey), grant.ownerProvider, grant.ownerSubject, grant.label, grant.createdAt],
      )
    }
  })
}

async function withTransaction(pool: Pool, body: (client: PoolClient) => Promise<void>): Promise<void> {
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    await body(client)
    await client.query('COMMIT')
    client.release()
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined)
    client.release(error instanceof Error ? error : new Error(String(error)))
    throw error
  }
}

function grantFromRow(row: GrantRow): AgentGrant | undefined {
  if (!isProviderName(row.owner_provider)) return undefined
  const publicKey = bytea(row.public_key)
  if (!publicKey) return undefined
  const createdAt = integerColumn(row.created_at)
  if (createdAt === undefined) return undefined
  return {
    ownerProvider: row.owner_provider,
    ownerSubject: row.owner_subject,
    publicKey,
    label: row.label,
    createdAt,
  }
}

function bytea(value: unknown): Uint8Array | undefined {
  if (typeof value === 'string') return undefined
  if (!(value instanceof Uint8Array)) return undefined
  return new Uint8Array(value)
}

function integerColumn(value: unknown): number | undefined {
  const parsed = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : Number.NaN
  if (!Number.isSafeInteger(parsed) || parsed < 0) return undefined
  return parsed
}

function isProviderName(value: string): value is ProviderName {
  return value === 'google' || value === 'apple' || value === 'facebook'
}

function asDatabaseUrlError(error: unknown): Error {
  if (error instanceof Error && (error.message === INVALID_SESSION_ROW || error.message === INVALID_GRANT_ROW)) {
    return error
  }
  if (error instanceof Error && error.message.startsWith('DATABASE_URL failed')) return error
  const detail = error instanceof Error ? error.message : String(error)
  const redacted = detail.replace(/postgres(?:ql)?:\/\/[^@\s]+@/gi, 'postgres://')
  return new Error(`DATABASE_URL failed: ${redacted}`, { cause: error })
}
