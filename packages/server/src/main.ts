import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { getPublicKey } from '@noble/ed25519'
import { agentRequestOk } from '@agenticage/proof'
import { agentSubject, type ProviderName } from './identity.js'
import {
  agentAudienceOk,
  connectingText,
  decideAgentProof,
  decideConnect,
  destinationName,
  type LoginSession,
} from './connect.js'
import { grantsFilePath, type AgentGrant } from './grants.js'
import { connectDatabase } from './pg-store.js'
import {
  createWriteQueue,
  isLoginSession,
  openJsonGrantStore,
  openJsonSessionStore,
  type GrantStore,
  type SessionStore,
} from './stores.js'

export type Exchange = (code: string) => Promise<{ subject: string; label: string }>

export type LoginProvider = {
  clientId: string
  exchange: Exchange
  authorizeUrl?: string
}

export type LoginServerOptions = {
  port?: number
  host?: string
  issuer: string
  keyId: string
  privateKey: Uint8Array
  derivationKey: Uint8Array
  publicKey?: Uint8Array
  now?: () => number
  providers?: Partial<Record<ProviderName, LoginProvider>>
  testLogin?: boolean
  sessionsFile?: string
  databaseUrl?: string
}

const PROVIDERS: ProviderName[] = ['google', 'apple', 'facebook']
const SESSION_COOKIE = 'valar_session'
const OAUTH_COOKIE = 'valar_oauth'
// Session id to revoke. Apple's cross-site POST does not send the Lax session cookie.
const PRIOR_COOKIE = 'valar_prior'
const SESSION_MAX_AGE = 400 * 24 * 60 * 60
// Apple posts the callback across sites. Lax would drop the nonce on that POST.
const OAUTH_FLAGS = 'HttpOnly; Secure; SameSite=None; Path=/'
const OAUTH_DOMAIN = 'valar.login.oauth.v1'
const OAUTH_SECONDS = 600
const LIMIT = { audience: 512, returnUrl: 4096, site: 200, label: 200, code: 2048 }
const ID_TOKEN = /^[A-Za-z0-9_-]{16,128}$/

const AUTHORIZE: Record<ProviderName, string> = {
  google: 'https://accounts.google.com/o/oauth2/v2/auth',
  apple: 'https://appleid.apple.com/auth/authorize',
  facebook: 'https://www.facebook.com/v26.0/dialog/oauth',
}

const NAMES: Record<ProviderName, string> = { google: 'Google', apple: 'Apple', facebook: 'Facebook' }

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message)
  }
}

type StoredSession = LoginSession & { id: string }

type PendingLogin = {
  provider: ProviderName
  nonce: string
  exp: number
} & ({ returnPath: string } | { audience: string; returnUrl: string; site?: string })

type AgentTicket = {
  id: string
  publicKey: Uint8Array
  label: string
  loopback?: string
  exp: number
}

type ProofCounts = {
  granted: number
  unauthorized: number
}

type Ctx = {
  issuer: string
  keyId: string
  privateKey: Uint8Array
  publicKey: Uint8Array
  derivationKey: Uint8Array
  now: () => number
  providers: Partial<Record<ProviderName, LoginProvider>>
  testLogin: boolean
  sessions: SessionStore
  grants: GrantStore
  tickets: Map<string, AgentTicket>
  usedNonces: Map<string, true>
  proofs: ProofCounts
}

type ConnectQuery = { audience: string; returnUrl: string; site?: string }

export async function startLogin(
  options: LoginServerOptions,
): Promise<{ url: string; close(): Promise<void> }> {
  if (options.privateKey.length !== 32) throw new Error('private key must be 32 bytes')
  if (options.derivationKey.length === 0) throw new Error('derivation key is empty')
  if (sameBytes(options.privateKey, options.derivationKey)) {
    throw new Error('derivation key and signing key must differ')
  }
  if (options.keyId.length === 0 || Buffer.byteLength(options.keyId) > 255) throw new Error('bad key id')
  const issuer = canonicalIssuer(options.issuer)
  const databaseUrl = (options.databaseUrl ?? process.env.DATABASE_URL ?? '').trim()
  let endPool: (() => Promise<void>) | undefined
  const releasePool = async () => {
    const end = endPool
    endPool = undefined
    await end?.()
  }
  try {
    let sessions: SessionStore
    let grants: GrantStore
    if (databaseUrl !== '') {
      const db = await connectDatabase(databaseUrl)
      sessions = db.sessions
      grants = db.grants
      endPool = () => db.close()
    } else {
      const sessionsFile = (options.sessionsFile ?? process.env.SIGNET_SESSIONS ?? '').trim()
      if (sessionsFile === '') throw new Error('SIGNET_SESSIONS is required')
      const queue = createWriteQueue()
      sessions = await openJsonSessionStore(sessionsFile, queue)
      grants = await openJsonGrantStore(grantsFilePath(sessionsFile), queue)
    }
    // Sync getPublicKey needs SHA-512. Importing @agenticage/proof wires it.
    const derived = getPublicKey(options.privateKey)
    if (options.publicKey && !sameBytes(options.publicKey, derived)) {
      throw new Error('public key does not match private key')
    }
    const ctx: Ctx = {
      issuer,
      keyId: options.keyId,
      privateKey: options.privateKey,
      publicKey: options.publicKey ?? derived,
      derivationKey: options.derivationKey,
      now: () => Math.floor(options.now ? options.now() : Date.now() / 1000),
      providers: options.providers ?? {},
      testLogin: options.testLogin ?? process.env.SIGNET_TEST === '1',
      sessions,
      grants,
      tickets: new Map(),
      usedNonces: new Map(),
      proofs: { granted: 0, unauthorized: 0 },
    }
    if (ctx.testLogin) process.stderr.write('SIGNET_TEST is on; POST /test-login can mint a session\n')

    const httpServer = createServer((req, res) => {
      void handle(req, res, ctx)
    })
    const host = options.host?.trim() || '127.0.0.1'
    try {
      await listen(httpServer, options.port ?? 0, host)
    } catch (error) {
      httpServer.close()
      throw error
    }
    const address = httpServer.address()
    if (!address || typeof address === 'string') {
      httpServer.close()
      throw new Error('expected a tcp port')
    }
    return {
      url: `http://${host}:${address.port}`,
      async close() {
        try {
          httpServer.closeAllConnections()
          await new Promise<void>((resolve, reject) => {
            httpServer.close((error) => (error ? reject(error) : resolve()))
          })
        } finally {
          await releasePool()
        }
      },
    }
  } catch (error) {
    await releasePool()
    throw error
  }
}

async function handle(req: IncomingMessage, res: ServerResponse, ctx: Ctx): Promise<void> {
  try {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const path = url.pathname
    if (path === '/connect') return await handleConnect(req, res, ctx, url)
    if (path === '/.well-known/signet-keys') return handleKeys(req, res, ctx)
    if (path === '/sign-out') return await handleSignOut(req, res, ctx, url)
    if (path === '/switch') return await handleSwitch(req, res, ctx, url)
    if (path === '/logout') return await handleLogout(req, res, ctx)
    if (path === '/test-login') return await handleTestLogin(req, res, ctx, url)
    if (path === '/metrics') return handleMetrics(req, res, ctx)
    if (path === '/agent-proof') return await handleAgentProof(req, res, ctx)
    if (path === '/agents') return await handleAgents(req, res, ctx)
    if (path === '/agents/ticket') return await handleAgentTicket(req, res, ctx)
    if (path === '/agents/approve') return await handleAgentApprove(req, res, ctx, url)
    if (path === '/agents/revoke') return await handleAgentRevoke(req, res, ctx)
    if (path === '/agents/skill') return handleAgentSkill(req, res)
    const auth = /^\/auth\/(google|apple|facebook)$/.exec(path)
    if (auth && isProvider(auth[1])) return handleAuth(req, res, ctx, url, auth[1])
    const callback = /^\/auth\/(google|apple|facebook)\/callback$/.exec(path)
    if (callback && isProvider(callback[1])) return await handleCallback(req, res, ctx, url, callback[1])
    const mark = /^\/marks\/(google|apple|facebook)\.svg$/.exec(path)
    if (mark && isProvider(mark[1])) return await handleMark(req, res, mark[1])
    sendText(res, 404, 'not found')
  } catch (error) {
    if (error instanceof HttpError) {
      if (!res.headersSent) sendText(res, error.status, error.message)
      return
    }
    const message = error instanceof Error ? error.message : String(error)
    process.stderr.write(`login failed: ${message}\n`)
    if (!res.headersSent) sendText(res, 500, 'error')
    else res.end()
  }
}

async function handleConnect(req: IncomingMessage, res: ServerResponse, ctx: Ctx, url: URL): Promise<void> {
  if (req.method !== 'GET') return sendText(res, 405, 'method not allowed', { allow: 'GET' })
  const query = connectQuery(url)
  if (!query) return sendText(res, 400, 'rejected')
  const stored = readSession(ctx, req.headers.cookie)
  const decision = decideConnect({
    session: stored ? { provider: stored.provider, subject: stored.subject, label: stored.label } : null,
    audience: query.audience,
    returnUrl: query.returnUrl,
    now: ctx.now(),
    issuer: ctx.issuer,
    keyId: ctx.keyId,
    privateKey: ctx.privateKey,
    derivationKey: ctx.derivationKey,
  })
  if (decision.type === 'reject') {
    return sendText(res, 400, 'rejected', undefined, stored ? [sessionCookie(stored.id, ctx.issuer)] : undefined)
  }
  if (decision.type === 'providers') {
    sendHtml(res, 200, providersPage(ctx, query))
    return
  }
  if (!stored) return sendText(res, 500, 'error')
  const text = connectingText(query.audience, stored.label, query.site)
  sendHtml(res, 200, connectingPage(text, decision.location), [sessionCookie(stored.id, ctx.issuer)])
}

function handleKeys(req: IncomingMessage, res: ServerResponse, ctx: Ctx): void {
  if (req.method !== 'GET') return sendText(res, 405, 'method not allowed', { allow: 'GET' })
  const body = JSON.stringify({
    keys: [{ id: ctx.keyId, publicKey: Buffer.from(ctx.publicKey).toString('base64') }],
  })
  sendText(res, 200, body, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
}

async function handleLogout(req: IncomingMessage, res: ServerResponse, ctx: Ctx): Promise<void> {
  if (req.method !== 'POST') return sendText(res, 405, 'method not allowed', { allow: 'POST' })
  const stored = readSession(ctx, req.headers.cookie)
  if (stored) ctx.sessions.delete(stored.id)
  try {
    await ctx.sessions.persist()
  } catch (error) {
    if (stored) ctx.sessions.set(stored.id, { provider: stored.provider, subject: stored.subject, label: stored.label })
    throw error
  }
  sendEmpty(res, 204, [
    clearCookie(SESSION_COOKIE, sessionFlags(ctx.issuer)),
    clearCookie(OAUTH_COOKIE, OAUTH_FLAGS),
    clearCookie(PRIOR_COOKIE, OAUTH_FLAGS),
  ])
}

function acceptedQuery(ctx: Ctx, url: URL): ConnectQuery | null {
  const query = connectQuery(url)
  if (!query) return null
  const decision = decideConnect({
    session: null,
    audience: query.audience,
    returnUrl: query.returnUrl,
    now: ctx.now(),
    issuer: ctx.issuer,
    keyId: ctx.keyId,
    privateKey: ctx.privateKey,
    derivationKey: ctx.derivationKey,
  })
  if (decision.type === 'reject') return null
  return query
}

function signOutLocation(query: ConnectQuery): string {
  const url = new URL(query.returnUrl)
  url.hash = 'signet-identity=signed-out'
  return url.href
}

function signOutPage(label: string, query: ConnectQuery): string {
  const action = escapeHtml(queryPath('/sign-out', query))
  return (
    '<!doctype html><html lang="en"><meta charset="utf-8"><title>Sign out</title><h1>Sign out</h1>' +
    `<p>You are signed in as ${escapeHtml(label)}.</p>` +
    `<form method="post" action="${action}"><button type="submit">Sign out</button></form></html>`
  )
}

async function handleSignOut(req: IncomingMessage, res: ServerResponse, ctx: Ctx, url: URL): Promise<void> {
  if (req.method !== 'GET' && req.method !== 'POST') {
    return sendText(res, 405, 'method not allowed', { allow: 'GET, POST' })
  }
  const query = acceptedQuery(ctx, url)
  if (!query) return sendText(res, 400, 'rejected')
  const stored = readSession(ctx, req.headers.cookie)
  if (req.method === 'GET' && stored) {
    sendHtml(res, 200, signOutPage(stored.label, query))
    return
  }
  if (req.method === 'POST' && stored) {
    ctx.sessions.delete(stored.id)
    try {
      await ctx.sessions.persist()
    } catch (error) {
      ctx.sessions.set(stored.id, { provider: stored.provider, subject: stored.subject, label: stored.label })
      throw error
    }
  }
  const location = signOutLocation(query)
  if (/[\r\n]/.test(location)) return sendText(res, 400, 'rejected')
  sendRedirect(res, 303, location, 'signed-out', [
    clearCookie(SESSION_COOKIE, sessionFlags(ctx.issuer)),
    clearCookie(OAUTH_COOKIE, OAUTH_FLAGS),
    clearCookie(PRIOR_COOKIE, OAUTH_FLAGS),
  ])
}

async function handleTestLogin(req: IncomingMessage, res: ServerResponse, ctx: Ctx, url: URL): Promise<void> {
  if (!ctx.testLogin) return sendText(res, 404, 'not found')
  if (req.method !== 'POST') return sendText(res, 405, 'method not allowed', { allow: 'POST' })
  const session = await readTestSession(req)
  if (!session) return sendText(res, 400, 'bad request')
  const hasNext = url.searchParams.has('next')
  const named = url.searchParams.has('audience') || url.searchParams.has('return') || url.searchParams.has('site')
  if (hasNext && named) return sendText(res, 400, 'rejected')
  if (hasNext) {
    const returnPath = agentReturnPath(ctx.issuer, url.searchParams.get('next') ?? '')
    if (!returnPath) return sendText(res, 400, 'rejected')
    const previous = readSession(ctx, req.headers.cookie)
    sendRedirect(res, 303, `${ctx.issuer}${returnPath}`, 'signed-in', [await issueSession(ctx, session, previous?.id)])
    return
  }
  const query = connectQuery(url)
  // No audience, return, or site mints a session. A present but unusable query must not.
  if (named && !query) return sendText(res, 400, 'rejected')
  if (query) {
    const decision = decideConnect({
      session,
      audience: query.audience,
      returnUrl: query.returnUrl,
      now: ctx.now(),
      issuer: ctx.issuer,
      keyId: ctx.keyId,
      privateKey: ctx.privateKey,
      derivationKey: ctx.derivationKey,
    })
    if (decision.type !== 'redirect') return sendText(res, 400, 'rejected')
    const previous = readSession(ctx, req.headers.cookie)
    const text = connectingText(query.audience, session.label, query.site)
    sendHtml(res, 200, connectingPage(text, decision.location), [await issueSession(ctx, session, previous?.id)])
    return
  }
  const previous = readSession(ctx, req.headers.cookie)
  sendEmpty(res, 204, [await issueSession(ctx, session, previous?.id)])
}

const LOCAL_TEST_SESSION: LoginSession = { provider: 'google', subject: 'local', label: 'Local' }

async function readTestSession(req: IncomingMessage): Promise<LoginSession | null> {
  let raw: string
  try {
    raw = await readBody(req)
  } catch (error) {
    if (error instanceof HttpError) throw error
    return null
  }
  const trimmed = raw.trim()
  if (trimmed === '') return LOCAL_TEST_SESSION
  if (!trimmed.startsWith('{')) return null
  let parsed: unknown
  try {
    parsed = JSON.parse(trimmed)
  } catch {
    return null
  }
  if (typeof parsed !== 'object' || parsed === null) return null
  const session = {
    provider: 'provider' in parsed ? parsed.provider : undefined,
    subject: 'subject' in parsed ? parsed.subject : undefined,
    label: 'label' in parsed ? parsed.label : undefined,
  }
  if (!isLoginSession(session)) return null
  return session
}

async function handleAgentProof(req: IncomingMessage, res: ServerResponse, ctx: Ctx): Promise<void> {
  if (req.method !== 'POST') return sendText(res, 405, 'method not allowed', { allow: 'POST' })
  let parsed: unknown
  try {
    parsed = JSON.parse(await readBody(req))
  } catch (error) {
    if (error instanceof HttpError) throw error
    return sendText(res, 400, 'rejected')
  }
  const body = agentProofBody(parsed)
  if (!body) return sendText(res, 400, 'rejected')
  const decision = decideAgentProof({
    audience: body.audience,
    publicKey: body.publicKey,
    issuedAt: body.issuedAt,
    signature: body.signature,
    now: ctx.now(),
    issuer: ctx.issuer,
    keyId: ctx.keyId,
    privateKey: ctx.privateKey,
    derivationKey: ctx.derivationKey,
    granted: ctx.grants.isGranted(body.publicKey),
  })
  if (decision.type === 'reject') return sendText(res, 400, 'rejected')
  if (decision.type === 'unauthorized') {
    ctx.proofs.unauthorized += 1
    const payload = JSON.stringify({ error: 'unauthorized', skill: `${ctx.issuer}/agents/skill` })
    return sendText(res, 403, payload, { 'content-type': 'application/json; charset=utf-8' })
  }
  ctx.proofs.granted += 1
  const proof = Buffer.from(decision.proof).toString('base64url')
  sendText(res, 200, JSON.stringify({ proof }), { 'content-type': 'application/json; charset=utf-8' })
}

function handleMetrics(req: IncomingMessage, res: ServerResponse, ctx: Ctx): void {
  if (req.method !== 'GET') return sendText(res, 405, 'method not allowed', { allow: 'GET' })
  const body = `signet_agent_proof_total ${ctx.proofs.granted}\nsignet_agent_proof_unauthorized_total ${ctx.proofs.unauthorized}\n`
  sendText(res, 200, body)
}

function agentProofBody(parsed: unknown): {
  audience: string
  publicKey: Uint8Array
  issuedAt: number
  signature: Uint8Array
} | null {
  if (typeof parsed !== 'object' || parsed === null) return null
  const audience = 'audience' in parsed ? parsed.audience : undefined
  const issuedAt = 'issuedAt' in parsed ? parsed.issuedAt : undefined
  const publicKey = 'publicKey' in parsed ? parsed.publicKey : undefined
  const signature = 'signature' in parsed ? parsed.signature : undefined
  if (typeof audience !== 'string' || audience.length > LIMIT.audience) return null
  if (typeof issuedAt !== 'number' || !Number.isInteger(issuedAt) || issuedAt < 0 || issuedAt > 0xffffffff) return null
  const key = base64urlBytes(publicKey, 32)
  const sig = base64urlBytes(signature, 64)
  if (!key || !sig) return null
  return { audience, publicKey: key, issuedAt, signature: sig }
}

function base64urlBytes(value: unknown, length: number): Uint8Array | null {
  if (typeof value !== 'string' || value.includes('=')) return null
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null
  const bytes = Buffer.from(value, 'base64url')
  if (bytes.length !== length || bytes.toString('base64url') !== value) return null
  return bytes
}

async function handleAgentTicket(req: IncomingMessage, res: ServerResponse, ctx: Ctx): Promise<void> {
  if (req.method !== 'POST') return sendText(res, 405, 'method not allowed', { allow: 'POST' })
  let parsed: unknown
  try {
    parsed = JSON.parse(await readBody(req))
  } catch (error) {
    if (error instanceof HttpError) throw error
    return sendText(res, 400, 'rejected')
  }
  const body = ticketBody(parsed)
  if (!body) return sendText(res, 400, 'rejected')
  if (!agentRequestOk(body.audience, body.publicKey, body.issuedAt, body.signature, ctx.now())) {
    return sendText(res, 400, 'rejected')
  }
  if (!agentAudienceOk(body.audience)) return sendText(res, 400, 'rejected')
  const ticket: AgentTicket = {
    id: randomBytes(16).toString('base64url'),
    publicKey: Uint8Array.from(body.publicKey),
    label: body.label,
    exp: ctx.now() + OAUTH_SECONDS,
  }
  if (body.loopback !== undefined) ticket.loopback = body.loopback
  rememberTicket(ctx, ticket)
  const approveUrl = `${ctx.issuer}${approvePath(ticket.id)}`
  const payload = JSON.stringify({ ticket: ticket.id, approveUrl })
  sendText(res, 200, payload, { 'content-type': 'application/json; charset=utf-8' })
}

function ticketBody(parsed: unknown): {
  audience: string
  publicKey: Uint8Array
  issuedAt: number
  signature: Uint8Array
  label: string
  loopback?: string
} | null {
  const proof = agentProofBody(parsed)
  if (!proof || typeof parsed !== 'object' || parsed === null) return null
  const label = 'label' in parsed ? parsed.label : undefined
  if (!validLabel(label)) return null
  if (!('loopback' in parsed) || parsed.loopback === undefined) return { ...proof, label }
  const loopback = loopbackOrigin(parsed.loopback)
  if (!loopback) return null
  return { ...proof, label, loopback }
}

function validLabel(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= LIMIT.label && !/[\r\n\0]/.test(value)
}

function loopbackOrigin(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > 200) return null
  if (/[\r\n\0\\\s]/.test(value)) return null
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return null
  }
  if (url.protocol !== 'http:') return null
  if (url.username !== '' || url.password !== '') return null
  if (url.hostname !== '127.0.0.1' && url.hostname !== 'localhost') return null
  if (url.port === '') return null
  const port = Number(url.port)
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null
  if (url.pathname !== '/' || url.search !== '' || url.hash !== '') return null
  const origin = `http://${url.hostname}:${port}`
  if (url.origin !== origin) return null
  if (value !== origin && value !== `${origin}/`) return null
  return origin
}

async function handleAgentApprove(req: IncomingMessage, res: ServerResponse, ctx: Ctx, url: URL): Promise<void> {
  if (req.method !== 'GET' && req.method !== 'POST') {
    return sendText(res, 405, 'method not allowed', { allow: 'GET, POST' })
  }
  const id = ticketId(url.searchParams.get('ticket'))
  if (!id) return sendText(res, 400, 'rejected')
  const ticket = liveTicket(ctx, id)
  if (!ticket) return sendText(res, 400, 'rejected')
  const session = readSession(ctx, req.headers.cookie)
  if (req.method === 'GET') {
    if (!session) {
      const intro = `To authorize an agent labeled ${ticket.label}, ${fingerprint(ticket.publicKey)}, choose an account.`
      sendHtml(res, 200, agentSignInPage(ctx, approvePath(ticket.id), intro))
      return
    }
    sendHtml(res, 200, allowPage(ticket))
    return
  }
  if (!session) return sendText(res, 400, 'rejected')
  const grant: AgentGrant = {
    ownerProvider: session.provider,
    ownerSubject: session.subject,
    publicKey: ticket.publicKey,
    label: ticket.label,
    createdAt: ctx.now(),
  }
  const existing = ctx.grants.get(ticket.publicKey)
  if (
    existing &&
    (existing.ownerProvider !== grant.ownerProvider || existing.ownerSubject !== grant.ownerSubject)
  ) {
    return sendText(res, 409, 'already allowed')
  }
  if (!(await commitGrant(ctx, grant))) return sendText(res, 400, 'rejected')
  ctx.tickets.delete(ticket.id)
  if (ticket.loopback !== undefined) {
    sendRedirect(res, 303, `${ticket.loopback}/#signet-agent=allowed`, 'allowed')
    return
  }
  sendHtml(res, 200, allowedPage(ticket.label))
}

async function handleAgents(req: IncomingMessage, res: ServerResponse, ctx: Ctx): Promise<void> {
  if (req.method !== 'GET') return sendText(res, 405, 'method not allowed', { allow: 'GET' })
  const session = readSession(ctx, req.headers.cookie)
  if (!session) {
    sendHtml(res, 200, agentSignInPage(ctx, '/agents', 'To see your agents, choose an account.'))
    return
  }
  sendHtml(res, 200, agentsPage(ctx.grants.listForOwner(session.provider, session.subject)))
}

async function handleAgentRevoke(req: IncomingMessage, res: ServerResponse, ctx: Ctx): Promise<void> {
  if (req.method !== 'POST') return sendText(res, 405, 'method not allowed', { allow: 'POST' })
  const session = readSession(ctx, req.headers.cookie)
  if (!session) return sendText(res, 400, 'rejected')
  const publicKey = await readRevokeKey(req)
  if (!publicKey) return sendText(res, 400, 'rejected')
  await commitRevoke(ctx, session.provider, session.subject, publicKey)
  sendRedirect(res, 303, '/agents', 'revoked')
}

async function readRevokeKey(req: IncomingMessage): Promise<Uint8Array | null> {
  let raw: string
  try {
    raw = await readBody(req)
  } catch (error) {
    if (error instanceof HttpError) throw error
    return null
  }
  const trimmed = raw.trim()
  if (trimmed.startsWith('{')) {
    try {
      const parsed: unknown = JSON.parse(trimmed)
      if (typeof parsed !== 'object' || parsed === null) return null
      const publicKey = 'publicKey' in parsed ? parsed.publicKey : undefined
      return base64urlBytes(publicKey, 32)
    } catch {
      return null
    }
  }
  return base64urlBytes(new URLSearchParams(raw).get('publicKey'), 32)
}

function handleAgentSkill(req: IncomingMessage, res: ServerResponse): void {
  if (req.method !== 'GET') return sendText(res, 405, 'method not allowed', { allow: 'GET' })
  sendText(res, 200, AGENT_SKILL, { 'content-type': 'text/markdown; charset=utf-8' })
}

const AGENT_SKILL = `# Allow this agent

Signet returns 403 from POST /agent-proof when this public key has no grant.

POST /agents/ticket with the same JSON fields as POST /agent-proof, and include label. label is 1 to 200 characters and must not contain a line break or a NUL. Include loopback only when you listen on http://127.0.0.1 or http://localhost with an explicit port. Signet rejects any other loopback.

A 200 response carries ticket and approveUrl. Show approveUrl to the person. Allow does not mint a secret. Keep the key you already have.

If you sent loopback, wait until the browser opens that origin with the fragment #signet-agent=allowed. Otherwise poll POST /agent-proof until the status is 200.

Send the person to /agents to revoke a grant. Each row has Revoke.
`

async function commitGrant(ctx: Ctx, grant: AgentGrant): Promise<boolean> {
  const existing = ctx.grants.get(grant.publicKey)
  const previous = existing ? copyGrant(existing) : undefined
  if (!ctx.grants.upsert(grant)) return false
  try {
    await ctx.grants.persist()
  } catch (error) {
    if (previous) ctx.grants.upsert(previous)
    else ctx.grants.revoke(grant.ownerProvider, grant.ownerSubject, grant.publicKey)
    throw error
  }
  return true
}

async function commitRevoke(
  ctx: Ctx,
  ownerProvider: ProviderName,
  ownerSubject: string,
  publicKey: Uint8Array,
): Promise<void> {
  const existing = ctx.grants.get(publicKey)
  if (!existing) return
  if (existing.ownerProvider !== ownerProvider || existing.ownerSubject !== ownerSubject) return
  const previous = copyGrant(existing)
  if (!ctx.grants.revoke(ownerProvider, ownerSubject, publicKey)) return
  try {
    await ctx.grants.persist()
  } catch (error) {
    ctx.grants.upsert(previous)
    throw error
  }
}

function copyGrant(grant: AgentGrant): AgentGrant {
  return {
    ownerProvider: grant.ownerProvider,
    ownerSubject: grant.ownerSubject,
    publicKey: Uint8Array.from(grant.publicKey),
    label: grant.label,
    createdAt: grant.createdAt,
  }
}

function rememberTicket(ctx: Ctx, ticket: AgentTicket): void {
  ctx.tickets.set(ticket.id, ticket)
  while (ctx.tickets.size > 10_000) {
    const oldest = ctx.tickets.keys().next().value
    if (oldest === undefined) break
    ctx.tickets.delete(oldest)
  }
}

function liveTicket(ctx: Ctx, id: string): AgentTicket | null {
  const ticket = ctx.tickets.get(id)
  if (!ticket) return null
  if (ticket.exp <= ctx.now()) {
    ctx.tickets.delete(id)
    return null
  }
  return ticket
}

function ticketId(value: string | null): string | null {
  if (!value || !ID_TOKEN.test(value)) return null
  return value
}

function approvePath(id: string): string {
  return `/agents/approve?ticket=${encodeURIComponent(id)}`
}

function fingerprint(publicKey: Uint8Array): string {
  const hex = agentSubject(publicKey)
  return `${hex.slice(0, 8)}...${hex.slice(-8)}`
}

function handleAuth(req: IncomingMessage, res: ServerResponse, ctx: Ctx, url: URL, provider: ProviderName): void {
  if (req.method !== 'GET') return sendText(res, 405, 'method not allowed', { allow: 'GET' })
  const config = configured(ctx, provider)
  if (!config) return sendText(res, 404, 'not found')
  const destination = authDestination(ctx, url)
  if (!destination) return sendText(res, 400, 'rejected')
  const nonce = randomBytes(16).toString('base64url')
  const exp = ctx.now() + OAUTH_SECONDS
  const pending: PendingLogin =
    destination.kind === 'agents'
      ? { provider, returnPath: destination.returnPath, nonce, exp }
      : destination.query.site === undefined
        ? { provider, audience: destination.query.audience, returnUrl: destination.query.returnUrl, nonce, exp }
        : {
            provider,
            audience: destination.query.audience,
            returnUrl: destination.query.returnUrl,
            site: destination.query.site,
            nonce,
            exp,
          }
  const state = seal(ctx.derivationKey, OAUTH_DOMAIN, JSON.stringify(pending))
  const prompt = url.searchParams.get('prompt') === 'select_account' ? 'select_account' : undefined
  const location = authorizeLocation(
    provider,
    config,
    `${ctx.issuer}/auth/${provider}/callback`,
    state,
    provider === 'google' ? prompt : undefined,
  )
  const stored = readSession(ctx, req.headers.cookie)
  const cookies = [`${OAUTH_COOKIE}=${encodeURIComponent(nonce)}; ${OAUTH_FLAGS}; Max-Age=600`]
  if (stored) cookies.push(`${PRIOR_COOKIE}=${encodeURIComponent(stored.id)}; ${OAUTH_FLAGS}; Max-Age=600`)
  else cookies.push(clearCookie(PRIOR_COOKIE, OAUTH_FLAGS))
  sendRedirect(res, 302, location, '', cookies)
}

async function handleCallback(
  req: IncomingMessage,
  res: ServerResponse,
  ctx: Ctx,
  url: URL,
  provider: ProviderName,
): Promise<void> {
  if (req.method !== 'GET' && req.method !== 'POST') {
    return sendText(res, 405, 'method not allowed', { allow: 'GET, POST' })
  }
  const config = configured(ctx, provider)
  if (!config) return sendText(res, 404, 'not found')
  const params = req.method === 'POST' ? new URLSearchParams(await readBody(req)) : url.searchParams
  const pending = openPending(ctx, params.get('state') ?? '')
  if (!pending || pending.provider !== provider) return sendText(res, 400, 'bad request')
  const nonce = readCookie(req.headers.cookie, OAUTH_COOKIE)
  if (!nonce || !sameString(nonce, pending.nonce) || ctx.usedNonces.has(pending.nonce)) {
    return sendText(res, 400, 'bad request')
  }
  remember(ctx.usedNonces, pending.nonce)
  const code = params.get('code') ?? ''
  const failed = params.get('error')
  if (failed || code.length === 0 || code.length > LIMIT.code) return failLogin(res, ctx.issuer, pending)
  let result: { subject: string; label: string }
  try {
    result = await config.exchange(code)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    process.stderr.write(`login exchange failed: ${message}\n`)
    return failLogin(res, ctx.issuer, pending)
  }
  const session = { provider, subject: result.subject, label: result.label }
  if (!isLoginSession(session)) return failLogin(res, ctx.issuer, pending)
  const previous = readSession(ctx, req.headers.cookie)
  const prior = readCookie(req.headers.cookie, PRIOR_COOKIE)
  const drop: string[] = []
  if (previous) drop.push(previous.id)
  if (prior !== undefined && ID_TOKEN.test(prior) && !drop.includes(prior)) drop.push(prior)
  const settled = [
    clearCookie(OAUTH_COOKIE, OAUTH_FLAGS),
    clearCookie(PRIOR_COOKIE, OAUTH_FLAGS),
  ]
  if ('returnPath' in pending) {
    sendRedirect(res, 303, `${ctx.issuer}${pending.returnPath}`, 'signed-in', [
      await issueSession(ctx, session, drop),
      ...settled,
    ])
    return
  }
  const decision = decideConnect({
    session,
    audience: pending.audience,
    returnUrl: pending.returnUrl,
    now: ctx.now(),
    issuer: ctx.issuer,
    keyId: ctx.keyId,
    privateKey: ctx.privateKey,
    derivationKey: ctx.derivationKey,
  })
  if (decision.type !== 'redirect') return failLogin(res, ctx.issuer, pending)
  const text = connectingText(pending.audience, session.label, pending.site)
  sendHtml(res, 200, connectingPage(text, decision.location), [await issueSession(ctx, session, drop), ...settled])
}

function failLogin(res: ServerResponse, issuer: string, pending: PendingLogin): void {
  const prior = clearCookie(PRIOR_COOKIE, OAUTH_FLAGS)
  if ('returnPath' in pending) {
    sendRedirect(res, 303, `${issuer}${pending.returnPath}`, 'failed', [clearCookie(OAUTH_COOKIE, OAUTH_FLAGS), prior])
    return
  }
  let location: string
  try {
    const url = new URL(pending.returnUrl)
    if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.origin !== pending.audience) {
      sendText(res, 400, 'rejected', undefined, [prior])
      return
    }
    url.hash = 'signet-identity=failed'
    location = url.href
  } catch {
    sendText(res, 400, 'rejected', undefined, [prior])
    return
  }
  sendRedirect(res, 303, location, 'failed', [clearCookie(OAUTH_COOKIE, OAUTH_FLAGS), prior])
}

function authDestination(ctx: Ctx, url: URL): { kind: 'agents'; returnPath: string } | { kind: 'site'; query: ConnectQuery } | null {
  const hasNext = url.searchParams.has('next')
  const hasSite = url.searchParams.has('audience') || url.searchParams.has('return') || url.searchParams.has('site')
  if (hasNext) {
    if (hasSite) return null
    const returnPath = agentReturnPath(ctx.issuer, url.searchParams.get('next') ?? '')
    if (!returnPath) return null
    return { kind: 'agents', returnPath }
  }
  const query = connectQuery(url)
  if (!query) return null
  const decision = decideConnect({
    session: null,
    audience: query.audience,
    returnUrl: query.returnUrl,
    now: ctx.now(),
    issuer: ctx.issuer,
    keyId: ctx.keyId,
    privateKey: ctx.privateKey,
    derivationKey: ctx.derivationKey,
  })
  if (decision.type === 'reject') return null
  return { kind: 'site', query }
}

function agentReturnPath(issuer: string, value: string): string | null {
  if (value.length === 0 || value.length > LIMIT.returnUrl) return null
  if (/[\r\n\0\\\s]/.test(value)) return null
  let url: URL
  try {
    url = new URL(value, issuer)
  } catch {
    return null
  }
  if (url.origin !== issuer || url.username !== '' || url.password !== '') return null
  if (url.hash !== '') return null
  if (url.pathname !== '/agents' && !url.pathname.startsWith('/agents/')) return null
  const canonical = `${url.pathname}${url.search}`
  if (canonical.length > LIMIT.returnUrl || /[\r\n\0]/.test(canonical)) return null
  return canonical
}

function connectQuery(url: URL): ConnectQuery | null {
  const audience = url.searchParams.get('audience') ?? ''
  const returnUrl = url.searchParams.get('return') ?? ''
  if (audience.length === 0 || audience.length > LIMIT.audience) return null
  if (returnUrl.length === 0 || returnUrl.length > LIMIT.returnUrl) return null
  if (/[\r\n\0]/.test(audience) || /[\r\n\0]/.test(returnUrl)) return null
  if (!url.searchParams.has('site')) return { audience, returnUrl }
  const site = url.searchParams.get('site') ?? ''
  if (site.length > LIMIT.site || /[\r\n\0]/.test(site)) return null
  return { audience, returnUrl, site }
}

const MARK_FILES = {
  google: fileURLToPath(new URL('../assets/google.svg', import.meta.url)),
  apple: fileURLToPath(new URL('../assets/apple.svg', import.meta.url)),
  facebook: fileURLToPath(new URL('../assets/facebook.svg', import.meta.url)),
} as const

async function handleMark(req: IncomingMessage, res: ServerResponse, provider: ProviderName): Promise<void> {
  if (req.method !== 'GET') return sendText(res, 405, 'method not allowed', { allow: 'GET' })
  const bytes = await readFile(MARK_FILES[provider])
  res.writeHead(200, {
    'content-type': 'image/svg+xml',
    'content-length': String(bytes.length),
    'cache-control': 'no-store',
  })
  res.end(bytes)
}

const ACCOUNT_STYLE =
  '.accounts{display:flex;flex-direction:column;gap:12px;max-width:320px}' +
  '.accounts a{display:flex;align-items:center;box-sizing:border-box;width:320px;height:40px;padding:0 12px;gap:12px;border:1px solid #747775;border-radius:4px;background:#fff;color:#1f1f1f;font:14px/20px sans-serif;text-decoration:none}' +
  '.accounts img{width:20px;height:20px;object-fit:contain;flex:none}' +
  '.accounts img.apple{width:40px;height:40px}'

function providersPage(ctx: Ctx, query: ConnectQuery): string {
  const links = PROVIDERS.flatMap((provider) => {
    if (!configured(ctx, provider)) return []
    return [{ href: authPath(provider, query), provider, label: `Continue with ${NAMES[provider]}` }]
  })
  const buttons = links
    .map((link) => {
      const href = escapeHtml(link.href)
      const label = escapeHtml(link.label)
      const mark = link.provider === 'apple' ? '40' : '20'
      return `<a class="account" href="${href}"><img class="${link.provider}" src="/marks/${link.provider}.svg" alt="" width="${mark}" height="${mark}">${label}</a>`
    })
    .join('')
  const test = ctx.testLogin ? testLoginForm(query) : ''
  const body =
    links.length === 0 && !ctx.testLogin
      ? '<h1>Sign in</h1><p>Sign-in is not set up.</p><p>no-provider</p>'
      : links.length === 0
        ? `<h1>Sign in</h1>${test}`
        : `<h1>Sign in</h1><p>To continue to ${escapeHtml(destinationName(query.audience, query.site))}, choose an account. You sign in on that site, then come back here.</p><div class="accounts">${buttons}</div>${test}`
  return `<!doctype html><html lang="en"><meta charset="utf-8"><title>Sign in</title><style>${ACCOUNT_STYLE}</style>${body}</html>`
}

function agentSignInPage(ctx: Ctx, returnPath: string, intro: string): string {
  const next = `next=${encodeURIComponent(returnPath)}`
  const buttons = PROVIDERS.flatMap((provider) => {
    if (!configured(ctx, provider)) return []
    const href = escapeHtml(`/auth/${provider}?${next}`)
    const label = escapeHtml(`Continue with ${NAMES[provider]}`)
    const mark = provider === 'apple' ? '40' : '20'
    return [
      `<a class="account" href="${href}"><img class="${provider}" src="/marks/${provider}.svg" alt="" width="${mark}" height="${mark}">${label}</a>`,
    ]
  }).join('')
  const test = ctx.testLogin
    ? `<form method="post" action="${escapeHtml(`/test-login?${next}`)}"><button type="submit">Sign in</button></form>`
    : ''
  const text = `<p>${escapeHtml(intro)}</p>`
  const body =
    buttons.length === 0 && !ctx.testLogin
      ? `<h1>Sign in</h1>${text}<p>Sign-in is not set up.</p><p>no-provider</p>`
      : buttons.length === 0
        ? `<h1>Sign in</h1>${text}${test}`
        : `<h1>Sign in</h1>${text}<div class="accounts">${buttons}</div>${test}`
  return `<!doctype html><html lang="en"><meta charset="utf-8"><title>Sign in</title><style>${ACCOUNT_STYLE}</style>${body}</html>`
}

function allowPage(ticket: AgentTicket): string {
  const action = escapeHtml(approvePath(ticket.id))
  const label = escapeHtml(ticket.label)
  const key = escapeHtml(fingerprint(ticket.publicKey))
  return (
    '<!doctype html><html lang="en"><meta charset="utf-8"><title>Allow agent</title><h1>Allow agent</h1>' +
    `<p>Allow ${label}, ${key}.</p>` +
    `<form method="post" action="${action}"><button type="submit">Allow</button></form></html>`
  )
}

function allowedPage(label: string): string {
  return (
    '<!doctype html><html lang="en"><meta charset="utf-8"><title>Allowed</title><h1>Allowed</h1>' +
    `<p>Allowed ${escapeHtml(label)}.</p></html>`
  )
}

function agentsPage(rows: AgentGrant[]): string {
  const items = rows
    .map((grant) => {
      const label = escapeHtml(grant.label)
      const key = escapeHtml(fingerprint(grant.publicKey))
      const wire = escapeHtml(Buffer.from(grant.publicKey).toString('base64url'))
      return (
        `<li>${label} <time>${grant.createdAt}</time> ${key} ` +
        `<form method="post" action="/agents/revoke"><input type="hidden" name="publicKey" value="${wire}">` +
        '<button type="submit">Revoke</button></form></li>'
      )
    })
    .join('')
  const list = rows.length === 0 ? '<p>No agents.</p>' : `<ul>${items}</ul>`
  return `<!doctype html><html lang="en"><meta charset="utf-8"><title>Agents</title><h1>Agents</h1>${list}</html>`
}

function switchPage(ctx: Ctx, query: ConnectQuery, label: string): string {
  const links = PROVIDERS.flatMap((provider) => {
    if (!configured(ctx, provider)) return []
    return [{
      href: authPath(provider, query, provider === 'google' ? 'select_account' : undefined),
      provider,
      label: `Continue with ${NAMES[provider]}`,
    }]
  })
  const buttons = links
    .map((link) => {
      const href = escapeHtml(link.href)
      const text = escapeHtml(link.label)
      const mark = link.provider === 'apple' ? '40' : '20'
      return `<a class="account" href="${href}"><img class="${link.provider}" src="/marks/${link.provider}.svg" alt="" width="${mark}" height="${mark}">${text}</a>`
    })
    .join('')
  const test = ctx.testLogin ? testLoginForm(query) : ''
  const sentence = `<p>You are signed in as ${escapeHtml(label)}.</p>`
  const body =
    links.length === 0 && !ctx.testLogin
      ? `<h1>Switch account</h1>${sentence}<p>Sign-in is not set up.</p><p>no-provider</p>`
      : links.length === 0
        ? `<h1>Switch account</h1>${sentence}${test}`
        : `<h1>Switch account</h1>${sentence}<div class="accounts">${buttons}</div>${test}`
  return `<!doctype html><html lang="en"><meta charset="utf-8"><title>Switch account</title><style>${ACCOUNT_STYLE}</style>${body}</html>`
}

async function handleSwitch(req: IncomingMessage, res: ServerResponse, ctx: Ctx, url: URL): Promise<void> {
  if (req.method !== 'GET') return sendText(res, 405, 'method not allowed', { allow: 'GET' })
  const query = acceptedQuery(ctx, url)
  if (!query) return sendText(res, 400, 'rejected')
  const stored = readSession(ctx, req.headers.cookie)
  if (!stored) {
    sendHtml(res, 200, providersPage(ctx, query))
    return
  }
  sendHtml(res, 200, switchPage(ctx, query, stored.label))
}

function testLoginForm(query: ConnectQuery): string {
  const action = escapeHtml(queryPath('/test-login', query))
  return `<form method="post" action="${action}"><button type="submit">Sign in</button></form>`
}

function authPath(provider: ProviderName, query: ConnectQuery, prompt?: 'select_account'): string {
  const path = queryPath(`/auth/${provider}`, query)
  if (prompt === undefined) return path
  const params = new URLSearchParams(path.slice(path.indexOf('?') + 1))
  params.set('prompt', prompt)
  return `${path.slice(0, path.indexOf('?'))}?${params.toString()}`
}

function connectingPage(text: string, location: string): string {
  const shown = escapeHtml(text)
  const href = escapeHtml(location)
  const scriptUrl = JSON.stringify(location).replace(/</g, '\\u003c')
  return `<!doctype html><html lang="en"><meta charset="utf-8"><title>${shown}</title><meta http-equiv="refresh" content="1;url=${href}"><p>${shown}</p><script>setTimeout(function(){location.replace(${scriptUrl})},1000)</script></html>`
}

function queryPath(path: string, query: ConnectQuery): string {
  const params = new URLSearchParams({ audience: query.audience, return: query.returnUrl })
  if (query.site !== undefined) params.set('site', query.site)
  return `${path}?${params.toString()}`
}

function configured(ctx: Ctx, provider: ProviderName): LoginProvider | undefined {
  const found = ctx.providers[provider]
  if (!found || found.clientId.trim() === '') return undefined
  return { ...found, clientId: found.clientId.trim() }
}

function authorizeLocation(
  provider: ProviderName,
  config: LoginProvider,
  redirectUri: string,
  state: string,
  prompt?: 'select_account',
): string {
  const url = new URL(config.authorizeUrl ?? AUTHORIZE[provider])
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new HttpError(500, 'error')
  url.searchParams.set('client_id', config.clientId)
  url.searchParams.set('redirect_uri', redirectUri)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('state', state)
  if (provider === 'google') url.searchParams.set('scope', 'openid email profile')
  if (provider === 'google' && prompt === 'select_account') url.searchParams.set('prompt', 'select_account')
  if (provider === 'apple') {
    url.searchParams.set('scope', 'name email')
    url.searchParams.set('response_mode', 'form_post')
  }
  if (provider === 'facebook') url.searchParams.set('scope', 'email,public_profile')
  if (/[\r\n]/.test(url.href)) throw new HttpError(500, 'error')
  return url.href
}

async function issueSession(ctx: Ctx, session: LoginSession, previousId?: string | string[]): Promise<string> {
  const id = randomBytes(16).toString('base64url')
  const ids = previousId === undefined ? [] : Array.isArray(previousId) ? previousId : [previousId]
  const saved: Array<[string, LoginSession]> = []
  for (const prior of new Set(ids)) {
    const record = ctx.sessions.get(prior)
    if (record !== undefined) saved.push([prior, record])
    ctx.sessions.delete(prior)
  }
  ctx.sessions.set(id, session)
  try {
    await ctx.sessions.persist()
  } catch (error) {
    ctx.sessions.delete(id)
    for (const [prior, record] of saved) ctx.sessions.set(prior, record)
    throw error
  }
  return sessionCookie(id, ctx.issuer)
}

function sessionCookie(id: string, issuer: string): string {
  return `${SESSION_COOKIE}=${encodeURIComponent(id)}; ${sessionFlags(issuer)}; Max-Age=${SESSION_MAX_AGE}`
}

// Browsers keep a Secure cookie on https and on loopback http. They drop it for any other http origin.
function sessionFlags(issuer: string): string {
  const secure = secureSessionCookie(issuer) ? 'Secure; ' : ''
  return `HttpOnly; ${secure}SameSite=Lax; Path=/`
}

function secureSessionCookie(issuer: string): boolean {
  const url = new URL(issuer)
  if (url.protocol !== 'http:') return true
  return url.hostname === 'localhost' || url.hostname === '::1' || isLoopbackV4(url.hostname)
}

function isLoopbackV4(host: string): boolean {
  const parts = host.split('.')
  if (parts.length !== 4 || parts[0] !== '127') return false
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}

function readSession(ctx: Ctx, header: string | undefined): StoredSession | null {
  const id = readCookie(header, SESSION_COOKIE)
  if (!id || !ID_TOKEN.test(id)) return null
  const session = ctx.sessions.get(id)
  if (!session) return null
  return { id, provider: session.provider, subject: session.subject, label: session.label }
}

function openPending(ctx: Ctx, token: string): PendingLogin | null {
  const raw = unseal(ctx.derivationKey, OAUTH_DOMAIN, token)
  if (!raw) return null
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return null
  }
  if (typeof parsed !== 'object' || parsed === null) return null
  const provider = 'provider' in parsed ? parsed.provider : undefined
  const audience = 'audience' in parsed ? parsed.audience : undefined
  const returnUrl = 'returnUrl' in parsed ? parsed.returnUrl : undefined
  const nonce = 'nonce' in parsed ? parsed.nonce : undefined
  const exp = 'exp' in parsed ? parsed.exp : undefined
  const site = 'site' in parsed ? parsed.site : undefined
  if (!isProvider(provider)) return null
  if (typeof nonce !== 'string' || !ID_TOKEN.test(nonce) || typeof exp !== 'number' || !Number.isInteger(exp)) return null
  if (exp <= ctx.now()) return null
  const returnPathRaw = 'returnPath' in parsed ? parsed.returnPath : undefined
  if (returnPathRaw !== undefined) {
    if (audience !== undefined || returnUrl !== undefined || site !== undefined) return null
    if (typeof returnPathRaw !== 'string') return null
    const returnPath = agentReturnPath(ctx.issuer, returnPathRaw)
    if (returnPath !== returnPathRaw) return null
    return { provider, nonce, exp, returnPath }
  }
  if (typeof audience !== 'string' || typeof returnUrl !== 'string') return null
  if (audience.length > LIMIT.audience || returnUrl.length > LIMIT.returnUrl) return null
  if (site === undefined) return { provider, audience, returnUrl, nonce, exp }
  if (typeof site !== 'string' || site.length > LIMIT.site) return null
  return { provider, audience, returnUrl, site, nonce, exp }
}

function isProvider(value: unknown): value is ProviderName {
  return value === 'google' || value === 'apple' || value === 'facebook'
}

function seal(key: Uint8Array, domain: string, payload: string): string {
  const body = Buffer.from(payload, 'utf8').toString('base64url')
  const sig = mac(key, domain, body).toString('base64url')
  return `${body}.${sig}`
}

function unseal(key: Uint8Array, domain: string, token: string): string | null {
  const dot = token.indexOf('.')
  if (dot <= 0 || token.indexOf('.', dot + 1) !== -1) return null
  const body = token.slice(0, dot)
  const sig = token.slice(dot + 1)
  const expected = mac(key, domain, body)
  const got = Buffer.from(sig, 'base64url')
  if (got.length !== expected.length || !timingSafeEqual(got, expected)) return null
  return Buffer.from(body, 'base64url').toString('utf8')
}

function mac(key: Uint8Array, domain: string, body: string): Buffer {
  return createHmac('sha256', key).update(domain).update('\0').update(body).digest()
}

function readCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined
  for (const part of header.split(';')) {
    const trimmed = part.trim()
    const eq = trimmed.indexOf('=')
    if (eq <= 0) continue
    if (trimmed.slice(0, eq) !== name) continue
    try {
      return decodeURIComponent(trimmed.slice(eq + 1))
    } catch {
      return undefined
    }
  }
  return undefined
}

function clearCookie(name: string, flags: string): string {
  return `${name}=; ${flags}; Max-Age=0`
}

function remember(map: Map<string, true>, value: string): void {
  map.set(value, true)
  while (map.size > 10_000) {
    const oldest = map.keys().next().value
    if (oldest === undefined) break
    map.delete(oldest)
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false
  return timingSafeEqual(a, b)
}

function sameString(a: string, b: string): boolean {
  const left = Buffer.from(a)
  const right = Buffer.from(b)
  return left.length === right.length && timingSafeEqual(left, right)
}

function canonicalIssuer(issuer: string): string {
  let url: URL
  try {
    url = new URL(issuer)
  } catch {
    throw new Error('bad issuer')
  }
  if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.origin !== issuer) throw new Error('bad issuer')
  return url.origin
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => {
    if (ch === '&') return '&amp;'
    if (ch === '<') return '&lt;'
    if (ch === '>') return '&gt;'
    if (ch === '"') return '&quot;'
    return '&#39;'
  })
}

function sendText(res: ServerResponse, status: number, body: string, extra?: Record<string, string>, cookies?: string[]): void {
  if (cookies && cookies.length > 0) res.setHeader('Set-Cookie', cookies)
  const buf = Buffer.from(body)
  res.writeHead(status, {
    'content-type': 'text/plain; charset=utf-8',
    'content-length': String(buf.length),
    'cache-control': 'no-store',
    ...extra,
  })
  res.end(buf)
}

function sendHtml(res: ServerResponse, status: number, body: string, cookies?: string[]): void {
  sendText(res, status, body, { 'content-type': 'text/html; charset=utf-8' }, cookies)
}

function sendEmpty(res: ServerResponse, status: number, cookies?: string[]): void {
  if (cookies && cookies.length > 0) res.setHeader('Set-Cookie', cookies)
  res.writeHead(status, { 'cache-control': 'no-store' })
  res.end()
}

function sendRedirect(res: ServerResponse, status: number, location: string, body: string, cookies?: string[]): void {
  if (/[\r\n]/.test(location)) return sendText(res, 400, 'rejected')
  sendText(res, status, body, { location, 'content-type': 'text/plain; charset=utf-8' }, cookies)
}

function readBody(req: IncomingMessage, limit = 16_384): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let total = 0
    let settled = false
    const fail = (error: Error) => {
      if (settled) return
      settled = true
      reject(error)
    }
    req.on('data', (chunk: Buffer | string) => {
      if (settled) return
      const buf = typeof chunk === 'string' ? Buffer.from(chunk) : chunk
      total += buf.length
      if (total > limit) {
        req.destroy()
        fail(new HttpError(400, 'bad request'))
        return
      }
      chunks.push(buf)
    })
    req.on('end', () => {
      if (settled) return
      settled = true
      resolve(Buffer.concat(chunks).toString('utf8'))
    })
    req.on('error', () => fail(new HttpError(400, 'bad request')))
  })
}

function listen(server: Server, port: number, host: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (error: Error) => {
      server.off('error', onError)
      reject(error)
    }
    server.once('error', onError)
    server.listen(port, host, () => {
      server.off('error', onError)
      resolve()
    })
  })
}

function loginFromEnv(): LoginServerOptions {
  const port = Number(process.env.SIGNET_PORT ?? '8787')
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('SIGNET_PORT is invalid')
  const host = process.env.SIGNET_HOST?.trim() || '127.0.0.1'
  const privateKey = envBytes('SIGNET_PRIVATE_KEY')
  if (privateKey.length !== 32) throw new Error('SIGNET_PRIVATE_KEY must be 32 bytes')
  const derivationKey = envBytes('SIGNET_DERIVATION_KEY')
  const keyId = process.env.SIGNET_KEY_ID ?? 'k1'
  const issuer = process.env.SIGNET_ISSUER ?? `http://${host}:${port}`
  const databaseUrl = process.env.DATABASE_URL?.trim()
  return {
    port,
    host,
    issuer,
    keyId,
    privateKey,
    derivationKey,
    providers: providersFromEnv(canonicalIssuer(issuer)),
    testLogin: process.env.SIGNET_TEST === '1',
    ...(databaseUrl ? { databaseUrl } : {}),
  }
}

function providersFromEnv(issuer: string): Partial<Record<ProviderName, LoginProvider>> {
  const providers: Partial<Record<ProviderName, LoginProvider>> = {}
  const googleId = process.env.SIGNET_GOOGLE_CLIENT_ID?.trim() ?? ''
  if (googleId !== '') {
    providers.google = {
      clientId: googleId,
      exchange: (code) =>
        exchangeOidc(code, {
          tokenUrl: 'https://oauth2.googleapis.com/token',
          clientId: googleId,
          clientSecret: secret('SIGNET_GOOGLE_CLIENT_SECRET'),
          redirectUri: `${issuer}/auth/google/callback`,
          issuers: ['https://accounts.google.com', 'accounts.google.com'],
          provider: 'google',
        }),
    }
  }
  const appleId = process.env.SIGNET_APPLE_CLIENT_ID?.trim() ?? ''
  // Apple's client secret is a short-lived JWT. The operator supplies it; this process does not mint one.
  if (appleId !== '') {
    providers.apple = {
      clientId: appleId,
      exchange: (code) =>
        exchangeOidc(code, {
          tokenUrl: 'https://appleid.apple.com/auth/token',
          clientId: appleId,
          clientSecret: secret('SIGNET_APPLE_CLIENT_SECRET'),
          redirectUri: `${issuer}/auth/apple/callback`,
          issuers: ['https://appleid.apple.com'],
          provider: 'apple',
        }),
    }
  }
  const facebookId = process.env.SIGNET_FACEBOOK_CLIENT_ID?.trim() ?? ''
  if (facebookId !== '') {
    providers.facebook = {
      clientId: facebookId,
      exchange: (code) =>
        exchangeFacebook(code, facebookId, secret('SIGNET_FACEBOOK_CLIENT_SECRET'), `${issuer}/auth/facebook/callback`),
    }
  }
  return providers
}

function secret(name: string): string {
  const value = process.env[name] ?? ''
  if (value === '') throw new Error(`missing ${name}`)
  return value
}

function envBytes(name: string): Uint8Array {
  const value = process.env[name]?.trim()
  if (!value) throw new Error(`${name} is required`)
  const bytes = Buffer.from(value, 'base64')
  if (bytes.length === 0 || bytes.toString('base64').replace(/=+$/u, '') !== value.replace(/=+$/u, '')) {
    throw new Error(`${name} must be base64`)
  }
  return bytes
}

type OidcExchange = {
  tokenUrl: string
  clientId: string
  clientSecret: string
  redirectUri: string
  issuers: string[]
  provider: ProviderName
}

async function exchangeOidc(code: string, input: OidcExchange): Promise<{ subject: string; label: string }> {
  const parsed = await postForm(
    input.tokenUrl,
    new URLSearchParams({
      code,
      client_id: input.clientId,
      client_secret: input.clientSecret,
      redirect_uri: input.redirectUri,
      grant_type: 'authorization_code',
    }),
  )
  const token = field(parsed, 'id_token')
  if (typeof token !== 'string') throw new Error('bad_token')
  const claims = readIdToken(token, input.issuers, input.clientId, Math.floor(Date.now() / 1000))
  return { subject: claims.sub, label: accountLabel(input.provider, claims.email, claims.emailVerified, claims.name) }
}

async function exchangeFacebook(
  code: string,
  clientId: string,
  clientSecret: string,
  redirectUri: string,
): Promise<{ subject: string; label: string }> {
  const parsed = await postForm(
    'https://graph.facebook.com/v26.0/oauth/access_token',
    new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
    }),
  )
  const access = field(parsed, 'access_token')
  if (typeof access !== 'string' || access.length === 0) throw new Error('bad_token')
  const me = await providerJson('https://graph.facebook.com/v26.0/me?fields=id,name,email', {
    authorization: `Bearer ${access}`,
  })
  const id = field(me, 'id')
  if (typeof id !== 'string' || id.length === 0) throw new Error('bad_token')
  const email = field(me, 'email')
  const name = field(me, 'name')
  return {
    subject: id,
    label: accountLabel('facebook', typeof email === 'string' ? email : undefined, undefined, typeof name === 'string' ? name : undefined),
  }
}

function accountLabel(
  provider: ProviderName,
  email: string | undefined,
  emailVerified: boolean | undefined,
  name: string | undefined,
): string {
  if (email && email.length > 0 && emailVerified !== false) return email
  if (name && name.length > 0) return `${provider} ${name}`
  return provider
}

// The id_token is the provider token endpoint's TLS response, and redirects are refused.
// The signature is not checked again. iss, aud, and exp still have to match this client.
function readIdToken(
  token: string,
  issuers: string[],
  clientId: string,
  now: number,
): { sub: string; email?: string; emailVerified?: boolean; name?: string } {
  const parts = token.split('.')
  if (parts.length !== 3 || !parts[1]) throw new Error('bad_token')
  let payload: unknown
  try {
    payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
  } catch {
    throw new Error('bad_token')
  }
  const iss = field(payload, 'iss')
  const aud = field(payload, 'aud')
  const sub = field(payload, 'sub')
  const exp = field(payload, 'exp')
  if (typeof iss !== 'string' || !issuers.includes(iss)) throw new Error('bad_token')
  const auds = typeof aud === 'string' ? [aud] : Array.isArray(aud) ? aud.filter((item) => typeof item === 'string') : []
  if (!auds.includes(clientId)) throw new Error('bad_token')
  if (typeof sub !== 'string' || sub.length === 0) throw new Error('bad_token')
  if (typeof exp !== 'number' || now > exp + 60) throw new Error('bad_token')
  const email = field(payload, 'email')
  const name = field(payload, 'name')
  return {
    sub,
    email: typeof email === 'string' ? email : undefined,
    emailVerified: emailVerified(field(payload, 'email_verified')),
    name: typeof name === 'string' ? name : undefined,
  }
}

function emailVerified(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value
  if (value === 'true') return true
  if (value === 'false') return false
  return undefined
}

function field(value: unknown, key: string): unknown {
  if (typeof value !== 'object' || value === null || !Object.hasOwn(value, key)) return undefined
  return (value as Record<string, unknown>)[key]
}

async function postForm(url: string, body: URLSearchParams): Promise<unknown> {
  return providerJson(url, { 'content-type': 'application/x-www-form-urlencoded' }, body)
}

async function providerJson(url: string, headers: Record<string, string>, body?: URLSearchParams): Promise<unknown> {
  const res = await fetch(url, {
    method: body ? 'POST' : 'GET',
    headers: { accept: 'application/json', ...headers },
    body,
    redirect: 'error',
    signal: AbortSignal.timeout(10_000),
  })
  if (!res.ok) throw new Error(`provider_status_${res.status}`)
  const text = await res.text()
  if (text.length > 1_000_000) throw new Error('provider_response')
  try {
    return JSON.parse(text) as unknown
  } catch {
    throw new Error('provider_response')
  }
}

function launchedDirectly(): boolean {
  const entry = process.argv[1]
  if (!entry || process.env.VITEST) return false
  return import.meta.url === pathToFileURL(entry).href
}

if (launchedDirectly()) {
  startLogin(loginFromEnv())
    .then((running) => {
      process.stdout.write(`${running.url}\n`)
    })
    .catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error)
      process.stderr.write(`${message}\n`)
      process.exit(1)
    })
}
