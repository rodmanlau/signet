import { randomBytes } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { readProofAudience, readProofExpiry, signAgentRequest, verifyProof } from '@agenticage/proof'

const USAGE = [
  'npm start -w @agenticage/client -- --agent <signet-origin> <audience> <agent-key-file> <public-key-file>',
  'npm start -w @agenticage/client -- --human <signet-origin> <audience> <public-key-file>',
]

const PAGE = `<!DOCTYPE html>
<meta charset="utf-8">
<title>Signet</title>
<p>Returning the proof to this process.</p>
<script>
fetch("/", { method: "POST", headers: { "content-type": "text/plain" }, body: location.hash })
</script>`

const base64url = /^[A-Za-z0-9_-]+$/

type Write = (line: string) => void

type Heard =
  | { kind: 'proof'; bytes: Uint8Array }
  | { kind: 'redirect'; reason: string }
  | { kind: 'listen'; reason: string }

export async function runSignetClient(argv: string[], write: Write): Promise<number> {
  const mode = argv[0]
  const both = argv.includes('--agent') && argv.includes('--human')
  if ((mode !== '--agent' && mode !== '--human') || both) return writeUsage(write)
  if (mode === '--agent' && argv.length !== 5) return writeUsage(write)
  if (mode === '--human' && argv.length !== 4) return writeUsage(write)
  if (mode === '--agent') return runAgent(argv[1] ?? '', argv[2] ?? '', argv[3] ?? '', argv[4] ?? '', write)
  return runHuman(argv[1] ?? '', argv[2] ?? '', argv[3] ?? '', write)
}

function writeUsage(write: Write): number {
  write(USAGE[0] ?? '')
  write(USAGE[1] ?? '')
  return 1
}

async function runAgent(
  origin: string,
  audience: string,
  keyFile: string,
  publicKeyFile: string,
  write: Write,
): Promise<number> {
  if (!isOrigin(origin)) {
    write(`1. Signet origin: ${origin}. bad origin`)
    return 1
  }
  write(`1. Signet origin: ${origin}`)
  if (!isOrigin(audience)) {
    write(`2. Audience: ${audience}. bad origin`)
    return 1
  }
  write(`2. Audience: ${audience}`)

  let loaded: { secret: Uint8Array; created: boolean }
  try {
    loaded = await loadAgentKey(keyFile)
  } catch (error) {
    write(`3. Agent key: ${errorMessage(error)}`)
    return 1
  }

  const issuedAt = Math.floor(Date.now() / 1000)
  let signed: { publicKey: Uint8Array; signature: Uint8Array }
  try {
    signed = signAgentRequest(audience, loaded.secret, issuedAt)
  } catch (error) {
    const message = errorMessage(error)
    write(`3. Agent key: ${message === 'bad_key' ? 'bad length.' : message}`)
    return 1
  }
  const verb = loaded.created ? 'created' : 'loaded'
  write(`3. Agent key: ${verb}. Public key: ${Buffer.from(signed.publicKey).toString('base64')}`)
  write(`4. Agent request signed. issuedAt: ${issuedAt}`)

  const body = JSON.stringify({
    audience,
    publicKey: Buffer.from(signed.publicKey).toString('base64url'),
    issuedAt,
    signature: Buffer.from(signed.signature).toString('base64url'),
  })
  let response: Response
  try {
    response = await fetch(`${origin}/agent-proof`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
    })
  } catch (error) {
    write(`5. POST ${origin}/agent-proof. ${errorMessage(error)}`)
    return 1
  }
  write(`5. POST ${origin}/agent-proof`)

  let text: string
  try {
    text = await response.text()
  } catch (error) {
    write(`6. HTTP ${response.status}. ${errorMessage(error)}`)
    return 1
  }
  if (response.status !== 200) {
    write(`6. HTTP ${response.status}. ${text.slice(0, 200)}`)
    return 1
  }
  const proof = decodeProofBody(text)
  if (proof === null) {
    write('6. HTTP 200. bad proof')
    return 1
  }
  write(`6. HTTP 200. Proof bytes: ${proof.byteLength}`)
  return finishProof(proof, origin, audience, publicKeyFile, 7, write)
}

async function runHuman(origin: string, audience: string, publicKeyFile: string, write: Write): Promise<number> {
  if (!isOrigin(origin)) {
    write(`1. Signet origin: ${origin}. bad origin`)
    return 1
  }
  write(`1. Signet origin: ${origin}`)
  const url = loopbackAudience(audience)
  if (url === null) {
    write(`2. Audience: ${audience}. The proof would be returned to that origin.`)
    return 1
  }
  write(`2. Audience: ${audience}`)

  const heard = await listenForProof(url, audience, origin, write)
  if (heard.kind === 'listen') {
    write(`3. Listening on ${audience}. ${heard.reason}`)
    return 1
  }
  if (heard.kind === 'redirect') {
    write(`5. Redirect. ${heard.reason}`)
    return 1
  }
  write(`5. Redirect. Proof bytes: ${heard.bytes.byteLength}`)
  return finishProof(heard.bytes, origin, audience, publicKeyFile, 6, write)
}

function listenForProof(url: URL, audience: string, origin: string, write: Write): Promise<Heard> {
  return new Promise((resolve) => {
    let settled = false
    let listening = false
    const finish = (heard: Heard) => {
      if (settled) return
      settled = true
      resolve(heard)
    }
    const server = createServer((req, res) => {
      if (req.method === 'GET') {
        sendPage(res)
        return
      }
      if (req.method !== 'POST') {
        res.writeHead(405, { allow: 'GET, POST' })
        res.end()
        return
      }
      void readLimited(req, 8192)
        .then((body) => {
          const heard = proofFromFragment(body)
          res.writeHead(204, { connection: 'close' })
          res.end(() => {
            server.close()
            finish(heard)
          })
        })
        .catch((error: unknown) => {
          const heard: Heard = { kind: 'redirect', reason: errorMessage(error) }
          if (res.headersSent) {
            server.close()
            finish(heard)
            return
          }
          res.writeHead(204, { connection: 'close' })
          res.end(() => {
            server.close()
            finish(heard)
          })
        })
    })
    server.on('error', (error) => {
      if (listening) return
      server.close()
      finish({ kind: 'listen', reason: errorMessage(error) })
    })
    server.listen(Number(url.port), url.hostname, () => {
      listening = true
      // A test that returns before POST must not hold the worker. An operator
      // run has no other handle, so the listen socket has to stay referenced.
      server.unref()
      if (process.env.VITEST !== 'true') server.ref()
      const params = new URLSearchParams()
      params.set('audience', audience)
      params.set('return', `${audience}/`)
      write(`3. Listening on ${audience}`)
      write(`4. Open ${origin}/connect?${params.toString()}`)
    })
  })
}

function sendPage(res: ServerResponse): void {
  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    connection: 'close',
  })
  res.end(PAGE)
}

function proofFromFragment(body: string): Heard {
  if (body.startsWith('#signet-identity=')) return { kind: 'redirect', reason: body }
  if (body.startsWith('#signet-proof=')) {
    const bytes = decodeBase64Url(body.slice('#signet-proof='.length))
    if (bytes === null) return { kind: 'redirect', reason: 'bad proof' }
    return { kind: 'proof', bytes }
  }
  return { kind: 'redirect', reason: 'bad proof' }
}

async function finishProof(
  proof: Uint8Array,
  issuer: string,
  audience: string,
  keyFile: string,
  step: number,
  write: Write,
): Promise<number> {
  let proofAudience: string
  try {
    proofAudience = readProofAudience(proof)
  } catch {
    write(`${step}. Audience: bad_proof`)
    return 1
  }
  write(`${step}. Audience: ${proofAudience}`)

  let expiry: number
  try {
    expiry = readProofExpiry(proof)
  } catch {
    write(`${step + 1}. Expiry: bad_proof`)
    return 1
  }
  const still = expiry > Math.floor(Date.now() / 1000) ? 'yes' : 'no'
  write(`${step + 1}. Expiry: ${expiry}. Still valid: ${still}`)

  const idStep = step + 2
  let text: string
  try {
    text = await readFile(keyFile, 'utf8')
  } catch (error) {
    write(`${idStep}. Identity: ${errorMessage(error)}`)
    return 1
  }
  let keys: { id: string; publicKey: Uint8Array }[]
  try {
    keys = parsePublicKeys(text)
  } catch (error) {
    write(`${idStep}. Identity: ${errorMessage(error)}`)
    return 1
  }
  try {
    const identity = verifyProof(proof, {
      issuer,
      audience,
      keys,
      nowSeconds: Math.floor(Date.now() / 1000),
    })
    write(`${idStep}. Identity: ${identity}`)
    return 0
  } catch {
    write(`${idStep}. Identity: bad_proof`)
    return 1
  }
}

function isOrigin(value: string): boolean {
  try {
    const url = new URL(value)
    return (url.protocol === 'http:' || url.protocol === 'https:') && url.origin === value
  } catch {
    return false
  }
}

function loopbackAudience(value: string): URL | null {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return null
  }
  if (url.protocol !== 'http:') return null
  if (url.hostname !== '127.0.0.1' && url.hostname !== 'localhost') return null
  if (url.port === '') return null
  if (url.origin !== value) return null
  return url
}

async function loadAgentKey(path: string): Promise<{ secret: Uint8Array; created: boolean }> {
  try {
    const bytes = new Uint8Array(await readFile(path))
    if (bytes.length !== 32) throw new Error('bad length.')
    return { secret: bytes, created: false }
  } catch (error) {
    if (!isMissing(error)) throw error
  }
  const created = new Uint8Array(randomBytes(32))
  await writeFile(path, created, { mode: 0o600, flag: 'wx' })
  return { secret: created, created: true }
}

function decodeProofBody(body: string): Uint8Array | null {
  let parsed: unknown
  try {
    parsed = JSON.parse(body)
  } catch {
    return null
  }
  if (typeof parsed !== 'object' || parsed === null || !('proof' in parsed)) return null
  const proof = parsed.proof
  if (typeof proof !== 'string') return null
  return decodeBase64Url(proof)
}

function decodeBase64Url(token: string): Uint8Array | null {
  if (!base64url.test(token)) return null
  const bytes = Buffer.from(token, 'base64url')
  if (bytes.byteLength === 0 || bytes.toString('base64url') !== token) return null
  return new Uint8Array(bytes)
}

function parsePublicKeys(text: string): { id: string; publicKey: Uint8Array }[] {
  const parsed: unknown = JSON.parse(text)
  if (!Array.isArray(parsed)) throw new Error('public key file must be a JSON array')
  return parsed.map((entry) => {
    if (typeof entry !== 'object' || entry === null) throw new Error('identity key must be an object')
    const id = 'id' in entry ? entry.id : undefined
    const publicKey = 'publicKey' in entry ? entry.publicKey : undefined
    if (typeof id !== 'string' || id.length === 0) throw new Error('identity key id must be a string')
    if (typeof publicKey !== 'string' || publicKey.length === 0) throw new Error('identity publicKey must be base64')
    return { id, publicKey: Uint8Array.from(Buffer.from(publicKey, 'base64')) }
  })
}

function readLimited(req: IncomingMessage, limit: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let total = 0
    let settled = false
    const done = (error?: unknown) => {
      if (settled) return
      settled = true
      if (error) reject(error instanceof Error ? error : new Error(String(error)))
      else resolve(Buffer.concat(chunks).toString('utf8'))
    }
    req.on('data', (chunk: Buffer | string) => {
      if (settled || total >= limit) return
      const buf = typeof chunk === 'string' ? Buffer.from(chunk) : chunk
      const room = limit - total
      const slice = room >= buf.length ? buf : buf.subarray(0, room)
      chunks.push(slice)
      total += slice.length
    })
    req.on('end', () => done())
    req.on('error', (error) => done(error))
  })
}

function isMissing(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT'
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}
