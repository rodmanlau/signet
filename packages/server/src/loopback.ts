import { timingSafeEqual } from 'node:crypto'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { pathToFileURL } from 'node:url'
import { getPublicKey } from '@noble/ed25519'
import { signProof } from '@agenticage/proof'
import { connectingText } from './connect.js'
import { deriveIdentity } from './identity.js'

// A separate process from production Signet. It signs one audience with its own keys.
export const LOOPBACK_AUDIENCE = 'http://127.0.0.1:8080'
export const LOOPBACK_PORT = 8790

const PROOF_SECONDS = 15 * 60
const LOOPBACK_LABEL = 'Local'
const LIMIT = { audience: 512, returnUrl: 4096, site: 200 }

export type LoopbackDecision = { type: 'reject' } | { type: 'redirect'; location: string }

export type LoopbackIssuerOptions = {
  port?: number
  issuer?: string
  keyId?: string
  privateKey: Uint8Array
  derivationKey: Uint8Array
  publicKey?: Uint8Array
  now?: () => number
}

type Ctx = {
  issuer: string
  keyId: string
  privateKey: Uint8Array
  publicKey: Uint8Array
  derivationKey: Uint8Array
  now: () => number
}

// The issuer claim has to be this process's own loopback origin, never the audience and never a public origin.
export function loopbackIssuerOrigin(issuer: string): string | null {
  let url: URL
  try {
    url = new URL(issuer)
  } catch {
    return null
  }
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1') return null
  if (url.port === '' || url.port === '0' || url.port === '8080') return null
  if (url.username !== '' || url.password !== '') return null
  if (url.origin !== issuer) return null
  return url.origin
}

export function decideLoopbackProof(input: {
  audience: string
  returnUrl: string
  now: number
  issuer: string
  keyId: string
  privateKey: Uint8Array
  derivationKey: Uint8Array
}): LoopbackDecision {
  // The signed audience is the constant. A caller-supplied audience is not signed.
  if (input.audience !== LOOPBACK_AUDIENCE) return { type: 'reject' }
  const issuer = loopbackIssuerOrigin(input.issuer)
  if (issuer === null) return { type: 'reject' }
  if (input.keyId.length === 0 || Buffer.byteLength(input.keyId) > 255) return { type: 'reject' }
  if (!Number.isInteger(input.now) || input.now < 0 || input.now > 0xffffffff - PROOF_SECONDS) return { type: 'reject' }

  let returnUrl: URL
  try {
    returnUrl = new URL(input.returnUrl)
  } catch {
    return { type: 'reject' }
  }
  if (returnUrl.protocol !== 'http:' || returnUrl.origin !== LOOPBACK_AUDIENCE) return { type: 'reject' }
  if (returnUrl.username !== '' || returnUrl.password !== '') return { type: 'reject' }
  if (/[\r\n\0]/.test(input.returnUrl)) return { type: 'reject' }

  const identity = deriveIdentity('google', 'local', new URL(LOOPBACK_AUDIENCE).hostname, input.derivationKey)
  const proof = signProof(
    {
      keyId: input.keyId,
      issuer,
      identity,
      audience: LOOPBACK_AUDIENCE,
      issuedAt: input.now,
      expiresAt: input.now + PROOF_SECONDS,
    },
    input.privateKey,
  )
  const token = Buffer.from(proof).toString('base64url')
  returnUrl.hash = `signet-proof=${token}`
  if (/[\r\n]/.test(returnUrl.href)) return { type: 'reject' }
  return { type: 'redirect', location: returnUrl.href }
}

export function loopbackFromEnv(env: NodeJS.ProcessEnv = process.env): LoopbackIssuerOptions {
  for (const name of ['SIGNET_PRIVATE_KEY', 'SIGNET_DERIVATION_KEY', 'SIGNET_TEST']) {
    const value = env[name]
    if (value !== undefined && value.trim() !== '') {
      throw new Error(`refusing to start the loopback issuer while ${name} is set`)
    }
  }
  const host = env.SIGNET_HOST?.trim()
  if (host !== undefined && host !== '' && host !== '127.0.0.1') {
    throw new Error('loopback issuer listens on 127.0.0.1')
  }
  const port = loopbackPort(env.SIGNET_LOOPBACK_PORT)
  const issuer = `http://127.0.0.1:${port}`
  const configured = env.SIGNET_ISSUER?.trim()
  if (configured !== undefined && configured !== '' && configured !== issuer) {
    throw new Error('loopback issuer origin must be http://127.0.0.1:<port>')
  }
  const keyId = env.SIGNET_LOOPBACK_KEY_ID?.trim() || 'k1'
  return {
    port,
    issuer,
    keyId,
    privateKey: envBytes(env, 'SIGNET_LOOPBACK_PRIVATE_KEY'),
    derivationKey: envBytes(env, 'SIGNET_LOOPBACK_DERIVATION_KEY'),
  }
}

export async function startLoopbackIssuer(
  options: LoopbackIssuerOptions,
): Promise<{ url: string; close(): Promise<void> }> {
  if (options.privateKey.length !== 32) throw new Error('private key must be 32 bytes')
  if (options.derivationKey.length === 0) throw new Error('derivation key is empty')
  if (sameBytes(options.privateKey, options.derivationKey)) {
    throw new Error('derivation key and signing key must differ')
  }
  const port = options.port ?? LOOPBACK_PORT
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('SIGNET_LOOPBACK_PORT is invalid')
  if (port === 8080) throw new Error('loopback issuer cannot listen on the audience port')
  const keyId = options.keyId ?? 'k1'
  if (keyId.length === 0 || Buffer.byteLength(keyId) > 255) throw new Error('bad key id')
  if (options.issuer !== undefined && loopbackIssuerOrigin(options.issuer) === null) {
    throw new Error('loopback issuer origin must be http://127.0.0.1:<port>')
  }
  if (options.issuer !== undefined && port !== 0 && options.issuer !== `http://127.0.0.1:${port}`) {
    throw new Error('loopback issuer origin must be http://127.0.0.1:<port>')
  }
  const derived = getPublicKey(options.privateKey)
  if (options.publicKey && !sameBytes(options.publicKey, derived)) {
    throw new Error('public key does not match private key')
  }

  const ctx: Ctx = {
    issuer: '',
    keyId,
    privateKey: options.privateKey,
    publicKey: derived,
    derivationKey: options.derivationKey,
    now: () => Math.floor(options.now ? options.now() : Date.now() / 1000),
  }
  const httpServer = createServer((req, res) => {
    void handle(req, res, ctx)
  })
  try {
    await listen(httpServer, port, '127.0.0.1')
  } catch (error) {
    httpServer.close()
    throw error
  }
  const address = httpServer.address()
  if (!address || typeof address === 'string') {
    httpServer.close()
    throw new Error('expected a tcp port')
  }
  const origin = `http://127.0.0.1:${address.port}`
  if (loopbackIssuerOrigin(origin) !== origin || (options.issuer !== undefined && options.issuer !== origin)) {
    await closeServer(httpServer)
    throw new Error('loopback issuer origin must be http://127.0.0.1:<port>')
  }
  ctx.issuer = origin
  return { url: origin, close: () => closeServer(httpServer) }
}

async function handle(req: IncomingMessage, res: ServerResponse, ctx: Ctx): Promise<void> {
  try {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/connect') return handleConnect(req, res, ctx, url)
    if (url.pathname === '/.well-known/signet-keys') return handleKeys(req, res, ctx)
    sendText(res, 404, 'not found')
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    process.stderr.write(`loopback issuer failed: ${message}\n`)
    if (!res.headersSent) sendText(res, 500, 'error')
    else res.end()
  }
}

function handleConnect(req: IncomingMessage, res: ServerResponse, ctx: Ctx, url: URL): void {
  if (req.method !== 'GET') return sendText(res, 405, 'method not allowed', { allow: 'GET' })
  const query = loopbackQuery(url)
  if (!query) return sendText(res, 400, 'rejected')
  const decision = decideLoopbackProof({
    audience: query.audience,
    returnUrl: query.returnUrl,
    now: ctx.now(),
    issuer: ctx.issuer,
    keyId: ctx.keyId,
    privateKey: ctx.privateKey,
    derivationKey: ctx.derivationKey,
  })
  if (decision.type === 'reject') return sendText(res, 400, 'rejected')
  const text = connectingText(LOOPBACK_AUDIENCE, LOOPBACK_LABEL, query.site)
  sendHtml(res, 200, connectingPage(text, decision.location))
}

function handleKeys(req: IncomingMessage, res: ServerResponse, ctx: Ctx): void {
  if (req.method !== 'GET') return sendText(res, 405, 'method not allowed', { allow: 'GET' })
  const body = JSON.stringify({
    keys: [{ id: ctx.keyId, publicKey: Buffer.from(ctx.publicKey).toString('base64') }],
  })
  sendText(res, 200, body, { 'content-type': 'application/json; charset=utf-8' })
}

function loopbackQuery(url: URL): { audience: string; returnUrl: string; site?: string } | null {
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

function loopbackPort(value: string | undefined): number {
  const text = value?.trim()
  const port = text === undefined || text === '' ? LOOPBACK_PORT : Number(text)
  if (!Number.isInteger(port) || port <= 0 || port > 65535 || port === 8080) {
    throw new Error('SIGNET_LOOPBACK_PORT is invalid')
  }
  return port
}

function envBytes(env: NodeJS.ProcessEnv, name: string): Uint8Array {
  const value = env[name]?.trim()
  if (!value) throw new Error(`${name} is required`)
  const bytes = Buffer.from(value, 'base64')
  if (bytes.length === 0 || bytes.toString('base64').replace(/=+$/u, '') !== value.replace(/=+$/u, '')) {
    throw new Error(`${name} must be base64`)
  }
  return bytes
}

function connectingPage(text: string, location: string): string {
  const shown = escapeHtml(text)
  const href = escapeHtml(location)
  const scriptUrl = JSON.stringify(location).replace(/</g, '\\u003c')
  return `<!doctype html><html lang="en"><meta charset="utf-8"><title>${shown}</title><meta http-equiv="refresh" content="1;url=${href}"><p>${shown}</p><script>setTimeout(function(){location.replace(${scriptUrl})},1000)</script></html>`
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

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false
  return timingSafeEqual(a, b)
}

function sendText(res: ServerResponse, status: number, body: string, extra?: Record<string, string>): void {
  const buf = Buffer.from(body)
  res.writeHead(status, {
    'content-type': 'text/plain; charset=utf-8',
    'content-length': String(buf.length),
    'cache-control': 'no-store',
    ...extra,
  })
  res.end(buf)
}

function sendHtml(res: ServerResponse, status: number, body: string): void {
  sendText(res, status, body, { 'content-type': 'text/html; charset=utf-8' })
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

function closeServer(server: Server): Promise<void> {
  server.closeAllConnections()
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()))
  })
}

function launchedDirectly(): boolean {
  const entry = process.argv[1]
  if (!entry || process.env.VITEST) return false
  return import.meta.url === pathToFileURL(entry).href
}

if (launchedDirectly()) {
  startLoopbackIssuer(loopbackFromEnv())
    .then((running) => {
      process.stderr.write(`loopback issuer signs only ${LOOPBACK_AUDIENCE}\n`)
      process.stdout.write(`${running.url}\n`)
    })
    .catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error)
      process.stderr.write(`${message}\n`)
      process.exit(1)
    })
}
