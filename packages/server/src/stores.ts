import { randomBytes } from 'node:crypto'
import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { basename, dirname, join } from 'node:path'
import type { LoginSession } from './connect.js'
import {
  isGranted as mapIsGranted,
  listForOwner as mapListForOwner,
  loadGrants,
  revokeGrant,
  upsertGrant,
  writeGrants,
  type AgentGrant,
} from './grants.js'
import { agentSubject, type ProviderName } from './identity.js'

export type WriteQueue = { run(task: () => Promise<void>): Promise<void> }

export type SessionStore = {
  get(id: string): LoginSession | undefined
  set(id: string, session: LoginSession): void
  delete(id: string): LoginSession | undefined
  persist(): Promise<void>
}

export type GrantStore = {
  get(publicKey: Uint8Array): AgentGrant | undefined
  isGranted(publicKey: Uint8Array): boolean
  upsert(grant: AgentGrant): boolean
  revoke(ownerProvider: ProviderName, ownerSubject: string, publicKey: Uint8Array): boolean
  listForOwner(ownerProvider: ProviderName, ownerSubject: string): AgentGrant[]
  persist(): Promise<void>
}

const SESSION_ID = /^[A-Za-z0-9_-]{16,128}$/
const SESSION_FILE_ERROR = 'SIGNET_SESSIONS must be a JSON object of sessions'
const SUBJECT_MAX = 512
const LABEL_MAX = 200

export function createWriteQueue(): WriteQueue {
  let tail: Promise<void> = Promise.resolve()
  return {
    async run(task) {
      const run = tail.then(task)
      tail = run.then(
        () => undefined,
        () => undefined,
      )
      await run
    },
  }
}

export async function openJsonSessionStore(file: string, queue: WriteQueue): Promise<SessionStore> {
  const sessions = await loadSessions(file)
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
      return queue.run(() => writeSessions(file, sessions))
    },
  }
}

export async function openJsonGrantStore(file: string, queue: WriteQueue): Promise<GrantStore> {
  const grants = await loadGrants(file)
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
      return queue.run(() => writeGrants(file, grants))
    },
  }
}

async function loadSessions(file: string): Promise<Map<string, LoginSession>> {
  let text: string
  try {
    text = await readFile(file, 'utf8')
  } catch (error) {
    if (isEnoent(error)) return new Map()
    throw error
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new Error(SESSION_FILE_ERROR)
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(SESSION_FILE_ERROR)
  }
  const sessions = new Map<string, LoginSession>()
  for (const [id, value] of Object.entries(parsed)) {
    if (!SESSION_ID.test(id) || typeof value !== 'object' || value === null) {
      throw new Error(SESSION_FILE_ERROR)
    }
    const session = {
      provider: 'provider' in value ? value.provider : undefined,
      subject: 'subject' in value ? value.subject : undefined,
      label: 'label' in value ? value.label : undefined,
    }
    if (!isLoginSession(session)) throw new Error(SESSION_FILE_ERROR)
    sessions.set(id, session)
  }
  return sessions
}

export function isLoginSession(value: {
  provider: unknown
  subject: unknown
  label: unknown
}): value is LoginSession {
  return (
    (value.provider === 'google' || value.provider === 'apple' || value.provider === 'facebook') &&
    typeof value.subject === 'string' &&
    value.subject.length > 0 &&
    value.subject.length <= SUBJECT_MAX &&
    typeof value.label === 'string' &&
    value.label.length > 0 &&
    value.label.length <= LABEL_MAX &&
    !/[\r\n\0]/.test(value.subject) &&
    !/[\r\n\0]/.test(value.label)
  )
}

async function writeSessions(file: string, sessions: Map<string, LoginSession>): Promise<void> {
  const body: Record<string, LoginSession> = {}
  for (const [id, session] of sessions) {
    body[id] = { provider: session.provider, subject: session.subject, label: session.label }
  }
  const dir = dirname(file)
  await mkdir(dir, { recursive: true })
  const tmp = join(dir, `.${basename(file)}.${randomBytes(6).toString('hex')}.tmp`)
  try {
    await writeFile(tmp, JSON.stringify(body), { encoding: 'utf8', mode: 0o600 })
    await chmod(tmp, 0o600)
    await rename(tmp, file)
    await chmod(file, 0o600)
  } catch (error) {
    await rm(tmp, { force: true }).catch(() => undefined)
    throw error
  }
}

function isEnoent(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT'
}
