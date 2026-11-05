import { randomBytes } from 'node:crypto'
import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { basename, dirname, join } from 'node:path'
import { agentSubject, type ProviderName } from './identity.js'

export type AgentGrant = {
  ownerProvider: ProviderName
  ownerSubject: string
  publicKey: Uint8Array
  label: string
  createdAt: number
}

export type AgentGrantRecord = {
  ownerProvider: ProviderName
  ownerSubject: string
  publicKey: string
  label: string
  createdAt: number
}

export type AgentGrantFile = AgentGrantRecord[]

export type GrantStore = Map<string, AgentGrant>

const SUBJECT_MAX = 512
const LABEL_MAX = 200

export function grantsFilePath(sessionsFile: string): string {
  return join(dirname(sessionsFile), 'agent-grants.json')
}

export async function loadGrants(file: string): Promise<GrantStore> {
  let text: string
  try {
    text = await readFile(file, 'utf8')
  } catch (error) {
    if (isEnoent(error)) return new Map()
    warnInvalid(file)
    return new Map()
  }
  try {
    const parsed: unknown = JSON.parse(text)
    const store = parseGrantFile(parsed)
    if (!store) {
      warnInvalid(file)
      return new Map()
    }
    return store
  } catch {
    warnInvalid(file)
    return new Map()
  }
}

export async function writeGrants(file: string, store: GrantStore): Promise<void> {
  const records: AgentGrantFile = []
  for (const grant of store.values()) {
    records.push({
      ownerProvider: grant.ownerProvider,
      ownerSubject: grant.ownerSubject,
      publicKey: Buffer.from(grant.publicKey).toString('base64url'),
      label: grant.label,
      createdAt: grant.createdAt,
    })
  }
  const dir = dirname(file)
  await mkdir(dir, { recursive: true })
  const tmp = join(dir, `.${basename(file)}.${randomBytes(6).toString('hex')}.tmp`)
  try {
    await writeFile(tmp, JSON.stringify(records), { encoding: 'utf8', mode: 0o600 })
    await chmod(tmp, 0o600)
    await rename(tmp, file)
    await chmod(file, 0o600)
  } catch (error) {
    await rm(tmp, { force: true }).catch(() => undefined)
    throw error
  }
}

export function isGranted(store: GrantStore, publicKey: Uint8Array): boolean {
  if (publicKey.length !== 32) return false
  return store.has(agentSubject(publicKey))
}

export function upsertGrant(store: GrantStore, grant: AgentGrant): boolean {
  if (!validGrant(grant)) return false
  const key = agentSubject(grant.publicKey)
  const existing = store.get(key)
  if (existing) {
    if (existing.ownerProvider !== grant.ownerProvider || existing.ownerSubject !== grant.ownerSubject) return false
    existing.label = grant.label
    return true
  }
  store.set(key, {
    ownerProvider: grant.ownerProvider,
    ownerSubject: grant.ownerSubject,
    publicKey: Uint8Array.from(grant.publicKey),
    label: grant.label,
    createdAt: grant.createdAt,
  })
  return true
}

export function revokeGrant(
  store: GrantStore,
  ownerProvider: ProviderName,
  ownerSubject: string,
  publicKey: Uint8Array,
): boolean {
  if (publicKey.length !== 32) return false
  const key = agentSubject(publicKey)
  const existing = store.get(key)
  if (!existing) return false
  if (existing.ownerProvider !== ownerProvider || existing.ownerSubject !== ownerSubject) return false
  store.delete(key)
  return true
}

function parseGrantFile(parsed: unknown): GrantStore | null {
  if (!Array.isArray(parsed)) return null
  const store: GrantStore = new Map()
  for (const item of parsed) {
    const grant = recordToGrant(item)
    if (!grant) return null
    const key = agentSubject(grant.publicKey)
    if (store.has(key)) return null
    store.set(key, grant)
  }
  return store
}

function recordToGrant(value: unknown): AgentGrant | null {
  if (typeof value !== 'object' || value === null) return null
  const ownerProvider = 'ownerProvider' in value ? value.ownerProvider : undefined
  const ownerSubject = 'ownerSubject' in value ? value.ownerSubject : undefined
  const publicKey = 'publicKey' in value ? value.publicKey : undefined
  const label = 'label' in value ? value.label : undefined
  const createdAt = 'createdAt' in value ? value.createdAt : undefined
  if (!isOwnerProvider(ownerProvider)) return null
  if (!boundedText(ownerSubject, SUBJECT_MAX) || !boundedText(label, LABEL_MAX)) return null
  if (typeof createdAt !== 'number' || !Number.isSafeInteger(createdAt) || createdAt < 0) return null
  const key = publicKeyBytes(publicKey)
  if (!key) return null
  return { ownerProvider, ownerSubject, publicKey: key, label, createdAt }
}

function validGrant(grant: AgentGrant): boolean {
  return (
    isOwnerProvider(grant.ownerProvider) &&
    boundedText(grant.ownerSubject, SUBJECT_MAX) &&
    boundedText(grant.label, LABEL_MAX) &&
    Number.isSafeInteger(grant.createdAt) &&
    grant.createdAt >= 0 &&
    grant.publicKey.length === 32
  )
}

function publicKeyBytes(value: unknown): Uint8Array | null {
  if (typeof value !== 'string' || value.includes('=')) return null
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null
  const bytes = Buffer.from(value, 'base64url')
  if (bytes.length !== 32 || bytes.toString('base64url') !== value) return null
  return Uint8Array.from(bytes)
}

function boundedText(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max && !/[\r\n\0]/.test(value)
}

function isOwnerProvider(value: unknown): value is ProviderName {
  return value === 'google' || value === 'apple' || value === 'facebook'
}

function warnInvalid(file: string): void {
  process.stderr.write(`invalid agent grants file ${file}; agent proofs stay unauthorized\n`)
}

function isEnoent(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT'
}
