import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { basename, dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { getPublicKey } from '@noble/ed25519'
import '@agenticage/proof'
import type { ProviderName } from './identity.js'
import { connectingText, decideAgentProof, decideConnect, destinationName, type LoginSession } from './connect.js'

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
}

const PROVIDERS: ProviderName[] = ['google', 'apple', 'facebook']
const SESSION_COOKIE = 'valar_session'
const OAUTH_COOKIE = 'valar_oauth'
const SESSION_MAX_AGE = 400 * 24 * 60 * 60
// Apple posts the callback across sites. Lax would drop the nonce on that POST.
const OAUTH_FLAGS = 'HttpOnly; Secure; SameSite=None; Path=/'
const OAUTH_DOMAIN = 'valar.login.oauth.v1'
const OAUTH_SECONDS = 600
const LIMIT = { audience: 512, returnUrl: 4096, site: 200, subject: 512, label: 200, code: 2048 }
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
  audience: string
  returnUrl: string
  site?: string
  nonce: string
  exp: number
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
  sessionsFile: string
  sessions: Map<string, LoginSession>
  writing: Promise<void>
  usedNonces: Map<string, true>
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
  const sessionsFile = (options.sessionsFile ?? process.env.SIGNET_SESSIONS ?? '').trim()
  if (sessionsFile === '') throw new Error('SIGNET_SESSIONS is required')
  const sessions = await loadSessions(sessionsFile)
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
    sessionsFile,
    sessions,
    writing: Promise.resolve(),
    usedNonces: new Map(),
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
      httpServer.closeAllConnections()
      await new Promise<void>((resolve, reject) => {
        httpServer.close((error) => (error ? reject(error) : resolve()))
      })
    },
  }
}

async function handle(req: IncomingMessage, res: ServerResponse, ctx: Ctx): Promise<void> {
  try {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const path = url.pathname
    if (path === '/connect') return await handleConnect(req, res, ctx, url)
    if (path === '/.well-known/signet-keys') return handleKeys(req, res, ctx)
    if (path === '/sign-out') return await handleSignOut(req, res, ctx, url)
    if (path === '/logout') return await handleLogout(req, res, ctx)
    if (path === '/test-login') return await handleTestLogin(req, res, ctx, url)
    if (path === '/agent-proof') return await handleAgentProof(req, res, ctx)
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
    await persist(ctx)
  } catch (error) {
    if (stored) ctx.sessions.set(stored.id, { provider: stored.provider, subject: stored.subject, label: stored.label })
    throw error
  }
  sendEmpty(res, 204, [clearCookie(SESSION_COOKIE, sessionFlags(ctx.issuer)), clearCookie(OAUTH_COOKIE, OAUTH_FLAGS)])
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
      await persist(ctx)
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
  ])
}

async function handleTestLogin(req: IncomingMessage, res: ServerResponse, ctx: Ctx, url: URL): Promise<void> {
  if (!ctx.testLogin) return sendText(res, 404, 'not found')
  if (req.method !== 'POST') return sendText(res, 405, 'method not allowed', { allow: 'POST' })
  const session = await readTestSession(req)
  if (!session) return sendText(res, 400, 'bad request')
  const query = connectQuery(url)
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
    const text = connectingText(query.audience, session.label, query.site)
    sendHtml(res, 200, connectingPage(text, decision.location), [await issueSession(ctx, session)])
    return
  }
  sendEmpty(res, 204, [await issueSession(ctx, session)])
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
  if (!validSession(session)) return null
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
  })
  if (decision.type === 'reject') return sendText(res, 400, 'rejected')
  const proof = Buffer.from(decision.proof).toString('base64url')
  sendText(res, 200, JSON.stringify({ proof }), { 'content-type': 'application/json; charset=utf-8' })
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

function handleAuth(req: IncomingMessage, res: ServerResponse, ctx: Ctx, url: URL, provider: ProviderName): void {
  if (req.method !== 'GET') return sendText(res, 405, 'method not allowed', { allow: 'GET' })
  const config = configured(ctx, provider)
  if (!config) return sendText(res, 404, 'not found')
  const query = connectQuery(url)
  if (!query) return sendText(res, 400, 'rejected')
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
  if (decision.type === 'reject') return sendText(res, 400, 'rejected')
  const nonce = randomBytes(16).toString('base64url')
  const pending: PendingLogin = {
    provider,
    audience: query.audience,
    returnUrl: query.returnUrl,
    nonce,
    exp: ctx.now() + OAUTH_SECONDS,
  }
  if (query.site !== undefined) pending.site = query.site
  const state = seal(ctx.derivationKey, OAUTH_DOMAIN, JSON.stringify(pending))
  const location = authorizeLocation(provider, config, `${ctx.issuer}/auth/${provider}/callback`, state)
  sendRedirect(res, 302, location, '', [`${OAUTH_COOKIE}=${encodeURIComponent(nonce)}; ${OAUTH_FLAGS}; Max-Age=600`])
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
  if (failed || code.length === 0 || code.length > LIMIT.code) return failLogin(res, pending)
  let result: { subject: string; label: string }
  try {
    result = await config.exchange(code)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    process.stderr.write(`login exchange failed: ${message}\n`)
    return failLogin(res, pending)
  }
  const session = { provider, subject: result.subject, label: result.label }
  if (!validSession(session)) return failLogin(res, pending)
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
  if (decision.type !== 'redirect') return failLogin(res, pending)
  const text = connectingText(pending.audience, session.label, pending.site)
  sendHtml(res, 200, connectingPage(text, decision.location), [
    await issueSession(ctx, session),
    clearCookie(OAUTH_COOKIE, OAUTH_FLAGS),
  ])
}

function failLogin(res: ServerResponse, pending: PendingLogin): void {
  let location: string
  try {
    const url = new URL(pending.returnUrl)
    if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.origin !== pending.audience) {
      sendText(res, 400, 'rejected')
      return
    }
    url.hash = 'signet-identity=failed'
    location = url.href
  } catch {
    sendText(res, 400, 'rejected')
    return
  }
  sendRedirect(res, 303, location, 'failed', [clearCookie(OAUTH_COOKIE, OAUTH_FLAGS)])
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

function testLoginForm(query: ConnectQuery): string {
  const action = escapeHtml(queryPath('/test-login', query))
  return `<form method="post" action="${action}"><button type="submit">Sign in</button></form>`
}

function authPath(provider: ProviderName, query: ConnectQuery): string {
  return queryPath(`/auth/${provider}`, query)
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

function authorizeLocation(provider: ProviderName, config: LoginProvider, redirectUri: string, state: string): string {
  const url = new URL(config.authorizeUrl ?? AUTHORIZE[provider])
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new HttpError(500, 'error')
  url.searchParams.set('client_id', config.clientId)
  url.searchParams.set('redirect_uri', redirectUri)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('state', state)
  if (provider === 'google') url.searchParams.set('scope', 'openid email profile')
  if (provider === 'apple') {
    url.searchParams.set('scope', 'name email')
    url.searchParams.set('response_mode', 'form_post')
  }
  if (provider === 'facebook') url.searchParams.set('scope', 'email,public_profile')
  if (/[\r\n]/.test(url.href)) throw new HttpError(500, 'error')
  return url.href
}

async function issueSession(ctx: Ctx, session: LoginSession): Promise<string> {
  const id = randomBytes(16).toString('base64url')
  ctx.sessions.set(id, session)
  try {
    await persist(ctx)
  } catch (error) {
    ctx.sessions.delete(id)
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
    throw new Error('SIGNET_SESSIONS must be a JSON object of sessions')
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('SIGNET_SESSIONS must be a JSON object of sessions')
  }
  const sessions = new Map<string, LoginSession>()
  for (const [id, value] of Object.entries(parsed)) {
    if (!ID_TOKEN.test(id) || typeof value !== 'object' || value === null) {
      throw new Error('SIGNET_SESSIONS must be a JSON object of sessions')
    }
    const session = {
      provider: 'provider' in value ? value.provider : undefined,
      subject: 'subject' in value ? value.subject : undefined,
      label: 'label' in value ? value.label : undefined,
    }
    if (!validSession(session)) throw new Error('SIGNET_SESSIONS must be a JSON object of sessions')
    sessions.set(id, session)
  }
  return sessions
}

async function persist(ctx: Ctx): Promise<void> {
  const run = ctx.writing.then(() => writeSessions(ctx.sessionsFile, ctx.sessions))
  ctx.writing = run.then(
    () => undefined,
    () => undefined,
  )
  await run
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
  if (!isProvider(provider) || typeof audience !== 'string' || typeof returnUrl !== 'string') return null
  if (typeof nonce !== 'string' || !ID_TOKEN.test(nonce) || typeof exp !== 'number' || !Number.isInteger(exp)) return null
  if (exp <= ctx.now()) return null
  if (audience.length > LIMIT.audience || returnUrl.length > LIMIT.returnUrl) return null
  const pending: PendingLogin = { provider, audience, returnUrl, nonce, exp }
  if (site === undefined) return pending
  if (typeof site !== 'string' || site.length > LIMIT.site) return null
  pending.site = site
  return pending
}

function validSession(value: {
  provider: unknown
  subject: unknown
  label: unknown
}): value is LoginSession {
  return (
    isProvider(value.provider) &&
    typeof value.subject === 'string' &&
    value.subject.length > 0 &&
    value.subject.length <= LIMIT.subject &&
    typeof value.label === 'string' &&
    value.label.length > 0 &&
    value.label.length <= LIMIT.label &&
    !/[\r\n\0]/.test(value.subject) &&
    !/[\r\n\0]/.test(value.label)
  )
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
  return {
    port,
    host,
    issuer,
    keyId,
    privateKey,
    derivationKey,
    providers: providersFromEnv(canonicalIssuer(issuer)),
    testLogin: process.env.SIGNET_TEST === '1',
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
