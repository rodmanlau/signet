import { readFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const require = createRequire(join(repoRoot, 'packages/server/package.json'))
const { Pool } = require('pg')

const migrationPath = join(repoRoot, 'packages/server/migrations/001_sessions_and_grants.sql')
const SESSION_ID = /^[A-Za-z0-9_-]{16,128}$/
const SUBJECT_MAX = 512
const LABEL_MAX = 200

const usage =
  'usage: DATABASE_URL=... node scripts/import-json-to-postgres.mjs --sessions <file> [--grants <file>] [--check]'

class ImportError extends Error {
  constructor(message) {
    super(message)
    this.name = 'ImportError'
  }
}

try {
  const code = await main()
  process.exit(code)
} catch (error) {
  process.stderr.write(`${report(error)}\n`)
  process.exit(1)
}

async function main() {
  const args = parseArgs(process.argv.slice(2))
  const databaseUrl = (process.env.DATABASE_URL ?? '').trim()
  if (databaseUrl === '') fail('DATABASE_URL is required')

  const sessions = parseSessions(await readSessions(args.sessionsPath), args.sessionsPath)
  const grants = await readGrants(args.grantsPath)
  const migrationSql = await readMigration()

  const pool = new Pool({ connectionString: databaseUrl, max: 1 })
  pool.on('error', (error) => {
    process.stderr.write(`postgres pool error: ${errorText(error)}\n`)
  })
  const client = await pool.connect()
  let committed = false
  try {
    await client.query('BEGIN')
    await client.query("SELECT set_config('client_min_messages', 'error', true)")
    await client.query(migrationSql)
    for (const session of sessions) {
      await client.query(
        `INSERT INTO sessions (id, provider, subject, label)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (id) DO UPDATE SET
           provider = EXCLUDED.provider,
           subject = EXCLUDED.subject,
           label = EXCLUDED.label`,
        [session.id, session.provider, session.subject, session.label],
      )
    }
    for (const grant of grants) {
      const updated = await client.query(
        `INSERT INTO agent_grants (public_key, owner_provider, owner_subject, label, created_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (public_key) DO UPDATE SET
           owner_provider = EXCLUDED.owner_provider,
           owner_subject = EXCLUDED.owner_subject,
           label = EXCLUDED.label,
           created_at = EXCLUDED.created_at
         WHERE agent_grants.owner_provider = EXCLUDED.owner_provider
           AND agent_grants.owner_subject = EXCLUDED.owner_subject
         RETURNING public_key`,
        [grant.publicKey, grant.ownerProvider, grant.ownerSubject, grant.label, grant.createdAt],
      )
      if (updated.rows.length !== 1) {
        const existing = await client.query(
          'SELECT owner_provider, owner_subject FROM agent_grants WHERE public_key = $1',
          [grant.publicKey],
        )
        const row = existing.rows[0]
        if (!row) throw new ImportError(`agent grant ${grant.wire} was not written`)
        throw new ImportError(
          `agent grant ${grant.wire} belongs to ${row.owner_provider} ${row.owner_subject}. Refusing to replace it with ${grant.ownerProvider} ${grant.ownerSubject}.`,
        )
      }
    }
    await client.query('COMMIT')
    committed = true
    const sessionsCount = await countRows(client, 'sessions')
    const grantsCount = await countRows(client, 'agent_grants')
    process.stdout.write(`sessions=${sessionsCount} grants=${grantsCount}\n`)
    if (args.check && (sessionsCount !== sessions.length || grantsCount !== grants.length)) {
      process.stderr.write(
        `count mismatch: database has sessions=${sessionsCount} grants=${grantsCount}, files have sessions=${sessions.length} grants=${grants.length}\n`,
      )
      return 1
    }
    return 0
  } catch (error) {
    if (!committed) await client.query('ROLLBACK').catch(() => undefined)
    throw error
  } finally {
    client.release()
    await pool.end()
  }
}

function parseArgs(argv) {
  let sessionsPath
  let grantsPath
  let check = false
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--check') {
      check = true
      continue
    }
    if (arg === '--sessions' || arg === '--grants') {
      const value = argv[i + 1]
      if (value === undefined || value.startsWith('--')) fail(`missing value for ${arg}`)
      i += 1
      if (arg === '--sessions') sessionsPath = resolve(value)
      else grantsPath = resolve(value)
      continue
    }
    fail(`unknown argument ${arg}`)
  }
  if (sessionsPath === undefined) fail('missing --sessions')
  return {
    sessionsPath,
    grantsPath: grantsPath ?? join(dirname(sessionsPath), 'agent-grants.json'),
    check,
  }
}

async function readMigration() {
  try {
    return await readFile(migrationPath, 'utf8')
  } catch (error) {
    if (isEnoent(error)) throw new ImportError(`migration file not found: ${migrationPath}`)
    throw error
  }
}

async function readSessions(path) {
  try {
    return await readFile(path, 'utf8')
  } catch (error) {
    if (isEnoent(error)) throw new ImportError(`sessions file not found: ${path}`)
    throw error
  }
}

function parseSessions(text, path) {
  let parsed
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new ImportError(`invalid sessions file ${path}`)
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new ImportError(`invalid sessions file ${path}`)
  }
  const sessions = []
  for (const [id, value] of Object.entries(parsed)) {
    if (!SESSION_ID.test(id) || typeof value !== 'object' || value === null || Array.isArray(value)) {
      throw new ImportError(`invalid sessions file ${path}`)
    }
    const provider = 'provider' in value ? value.provider : undefined
    const subject = 'subject' in value ? value.subject : undefined
    const label = 'label' in value ? value.label : undefined
    if (!isProvider(provider) || !boundedText(subject, SUBJECT_MAX) || !boundedText(label, LABEL_MAX)) {
      throw new ImportError(`invalid sessions file ${path}`)
    }
    sessions.push({ id, provider, subject, label })
  }
  return sessions
}

async function readGrants(path) {
  let text
  try {
    text = await readFile(path, 'utf8')
  } catch (error) {
    if (isEnoent(error)) return []
    throw error
  }
  return parseGrants(text, path)
}

function parseGrants(text, path) {
  let parsed
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new ImportError(`invalid agent grants file ${path}`)
  }
  if (!Array.isArray(parsed)) throw new ImportError(`invalid agent grants file ${path}`)
  const grants = []
  const seen = new Set()
  for (const item of parsed) {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) {
      throw new ImportError(`invalid agent grants file ${path}`)
    }
    const ownerProvider = 'ownerProvider' in item ? item.ownerProvider : undefined
    const ownerSubject = 'ownerSubject' in item ? item.ownerSubject : undefined
    const publicKey = 'publicKey' in item ? item.publicKey : undefined
    const label = 'label' in item ? item.label : undefined
    const createdAt = 'createdAt' in item ? item.createdAt : undefined
    if (!isProvider(ownerProvider) || !boundedText(ownerSubject, SUBJECT_MAX) || !boundedText(label, LABEL_MAX)) {
      throw new ImportError(`invalid agent grants file ${path}`)
    }
    if (typeof createdAt !== 'number' || !Number.isSafeInteger(createdAt) || createdAt < 0) {
      throw new ImportError(`invalid agent grants file ${path}`)
    }
    const key = publicKeyBytes(publicKey)
    if (!key) throw new ImportError(`invalid agent grants file ${path}`)
    const wire = key.toString('base64url')
    if (seen.has(wire)) throw new ImportError(`invalid agent grants file ${path}`)
    seen.add(wire)
    grants.push({
      ownerProvider,
      ownerSubject,
      publicKey: key,
      label,
      createdAt,
      wire,
    })
  }
  return grants
}

function publicKeyBytes(value) {
  if (typeof value !== 'string' || value.includes('=')) return null
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null
  const bytes = Buffer.from(value, 'base64url')
  if (bytes.length !== 32 || bytes.toString('base64url') !== value) return null
  return bytes
}

function isProvider(value) {
  return value === 'google' || value === 'apple' || value === 'facebook'
}

function boundedText(value, max) {
  return typeof value === 'string' && value.length > 0 && value.length <= max && !/[\r\n\0]/.test(value)
}

async function countRows(client, table) {
  const result = await client.query(`SELECT count(*)::int AS n FROM ${table}`)
  return Number(result.rows[0].n)
}

function isEnoent(error) {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT'
}

function errorText(error) {
  const message = error instanceof Error ? error.message : String(error)
  return message.replace(/postgres(?:ql)?:\/\/[^@\s]+@/gi, 'postgres://')
}

function report(error) {
  const message = errorText(error)
  if (error instanceof ImportError) return message
  if (message.startsWith('DATABASE_URL')) return message
  return `DATABASE_URL failed: ${message}`
}

function fail(message) {
  process.stderr.write(`${message}\n${usage}\n`)
  process.exit(1)
}
