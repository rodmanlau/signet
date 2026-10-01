import { createServer } from 'node:net'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { keygenAsync as generateKeyPair } from '@noble/ed25519'
import { signProof, verifyProof } from '@agenticage/proof'
import { expect, it } from 'vitest'
import { agentSubject, deriveIdentity } from '../../server/src/identity.js'
import { startLogin } from '../../server/src/main.js'
import { runSignetClient } from '../src/run.js'

const USAGE = [
  'npm start -w @agenticage/client -- --agent <signet-origin> <audience> <agent-key-file> <public-key-file>',
  'npm start -w @agenticage/client -- --human <signet-origin> <audience> <public-key-file>',
]

async function freePort(): Promise<number> {
  const server = createServer()
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('port')
  await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())))
  return address.port
}

async function waitFor(lines: string[], prefix: string): Promise<void> {
  const start = Date.now()
  while (!lines.some((line) => line.startsWith(prefix))) {
    if (Date.now() - start > 2000) throw new Error(`timed out waiting for ${prefix}`)
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
}

it('prints both commands when the switch is missing or repeated', async () => {
  for (const argv of [[], ['--agent', '--human'], ['--human', 'http://127.0.0.1:8787', 'http://127.0.0.1:9', '--agent']]) {
    const lines: string[] = []
    expect(await runSignetClient(argv, (line) => lines.push(line))).toBe(1)
    expect(lines).toEqual(USAGE)
  }
})

it('prints nine agent steps and hides the secret and the proof', async () => {
  const { secretKey, publicKey } = await generateKeyPair()
  const port = await freePort()
  const origin = `http://127.0.0.1:${port}`
  const dir = await mkdtemp(join(tmpdir(), 'signet-client-'))
  const sessions = join(dir, 'sessions.json')
  const agentKey = join(dir, 'agent.key')
  const publicKeys = join(dir, 'keys.json')
  await writeFile(
    publicKeys,
    JSON.stringify([{ id: 'k1', publicKey: Buffer.from(publicKey).toString('base64') }]),
  )
  const server = await startLogin({
    port,
    host: '127.0.0.1',
    issuer: origin,
    keyId: 'k1',
    privateKey: secretKey,
    publicKey,
    derivationKey: new TextEncoder().encode('signet-client-test'),
    now: () => Math.floor(Date.now() / 1000),
    testLogin: false,
    sessionsFile: sessions,
  })
  try {
    const lines: string[] = []
    const code = await runSignetClient(
      ['--agent', origin, 'http://127.0.0.1:8080', agentKey, publicKeys],
      (line) => lines.push(line),
    )
    expect(code).toBe(0)
    expect(lines).toHaveLength(9)
    expect(lines[0]).toBe(`1. Signet origin: ${origin}`)
    expect(lines[1]).toBe('2. Audience: http://127.0.0.1:8080')
    expect(lines[2]?.startsWith('3. Agent key: created. Public key: ')).toBe(true)
    expect(lines[3]).toMatch(/^4\. Agent request signed\. issuedAt: \d+$/)
    expect(lines[4]).toBe(`5. POST ${origin}/agent-proof`)
    expect(lines[5]).toMatch(/^6\. HTTP 200\. Proof bytes: \d+$/)
    expect(lines[6]).toBe('7. Audience: http://127.0.0.1:8080')
    expect(lines[7]).toMatch(/^8\. Expiry: \d+\. Still valid: yes$/)
    const secret = new Uint8Array(await readFile(agentKey))
    expect(secret).toHaveLength(32)
    const printed = lines.join('\n')
    expect(printed).not.toContain(Buffer.from(secret).toString('base64'))
    expect(printed).not.toContain(Buffer.from(secret).toString('hex'))
    expect(printed).not.toMatch(/[A-Za-z0-9_-]{80,}/)
    const expected = deriveIdentity(
      'agent',
      agentSubject(publicFromLog(lines[2] ?? '')),
      '127.0.0.1',
      new TextEncoder().encode('signet-client-test'),
    )
    expect(lines[8]).toBe(`9. Identity: ${expected}`)
    expect(expected).toMatch(/^[0-9a-f]{64}$/)
  } finally {
    await server.close()
    await rm(dir, { recursive: true, force: true })
  }
})

it('stops after a rejected agent proof', async () => {
  const { secretKey, publicKey } = await generateKeyPair()
  const port = await freePort()
  const origin = `http://127.0.0.1:${port}`
  const dir = await mkdtemp(join(tmpdir(), 'signet-client-'))
  await writeFile(join(dir, 'keys.json'), '[]')
  const server = await startLogin({
    port,
    host: '127.0.0.1',
    issuer: origin,
    keyId: 'k1',
    privateKey: secretKey,
    publicKey,
    derivationKey: new TextEncoder().encode('signet-client-test'),
    now: () => 0,
    testLogin: false,
    sessionsFile: join(dir, 'sessions.json'),
  })
  try {
    const lines: string[] = []
    const code = await runSignetClient(
      ['--agent', origin, 'http://127.0.0.1:8080', join(dir, 'agent.key'), join(dir, 'keys.json')],
      (line) => lines.push(line),
    )
    expect(code).toBe(1)
    expect(lines).toHaveLength(6)
    expect(lines[5]).toBe('6. HTTP 400. rejected')
    expect(lines.some((line) => line.startsWith('7.'))).toBe(false)
  } finally {
    await server.close()
    await rm(dir, { recursive: true, force: true })
  }
})

it('stops when the agent key is the wrong length', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'signet-client-'))
  try {
    const key = join(dir, 'agent.key')
    await writeFile(key, Uint8Array.of(1, 2, 3))
    const lines: string[] = []
    const code = await runSignetClient(
      ['--agent', 'http://127.0.0.1:8787', 'http://127.0.0.1:8080', key, join(dir, 'keys.json')],
      (line) => lines.push(line),
    )
    expect(code).toBe(1)
    expect(lines).toEqual([
      '1. Signet origin: http://127.0.0.1:8787',
      '2. Audience: http://127.0.0.1:8080',
      '3. Agent key: bad length.',
    ])
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

it('resolves file arguments from the directory where npm was started', async () => {
  const { secretKey, publicKey } = await generateKeyPair()
  const port = await freePort()
  const origin = `http://127.0.0.1:${port}`
  const invoked = await mkdtemp(join(tmpdir(), 'signet-client-invoked-'))
  const elsewhere = await mkdtemp(join(tmpdir(), 'signet-client-cwd-'))
  const keysDir = join(invoked, '.signet')
  await mkdir(keysDir)
  await writeFile(
    join(keysDir, 'keys.json'),
    JSON.stringify([{ id: 'k1', publicKey: Buffer.from(publicKey).toString('base64') }]),
  )
  const server = await startLogin({
    port,
    host: '127.0.0.1',
    issuer: origin,
    keyId: 'k1',
    privateKey: secretKey,
    publicKey,
    derivationKey: new TextEncoder().encode('signet-client-test'),
    now: () => Math.floor(Date.now() / 1000),
    testLogin: false,
    sessionsFile: join(invoked, 'sessions.json'),
  })
  const previousCwd = process.cwd()
  const previousInit = process.env.INIT_CWD
  process.chdir(elsewhere)
  process.env.INIT_CWD = invoked
  try {
    const lines: string[] = []
    const code = await runSignetClient(
      ['--agent', origin, 'http://127.0.0.1:8080', join('.signet', 'agent.key'), join('.signet', 'keys.json')],
      (line) => lines.push(line),
    )
    expect(code).toBe(0)
    expect(lines[2]?.startsWith('3. Agent key: created. Public key: ')).toBe(true)
    expect(lines[8]?.startsWith('9. Identity: ')).toBe(true)
    const secret = await readFile(join(keysDir, 'agent.key'))
    expect(secret).toHaveLength(32)
    await expect(readFile(join(elsewhere, '.signet', 'agent.key'))).rejects.toThrow()
  } finally {
    process.chdir(previousCwd)
    if (previousInit === undefined) delete process.env.INIT_CWD
    else process.env.INIT_CWD = previousInit
    await server.close()
    await rm(invoked, { recursive: true, force: true })
    await rm(elsewhere, { recursive: true, force: true })
  }
})

it('prints eight human steps from a posted fragment', async () => {
  const { secretKey, publicKey } = await generateKeyPair()
  const audience = `http://127.0.0.1:${await freePort()}`
  const signet = 'http://127.0.0.1:8787'
  const dir = await mkdtemp(join(tmpdir(), 'signet-client-'))
  const keyFile = join(dir, 'keys.json')
  await writeFile(keyFile, JSON.stringify([{ id: 'k1', publicKey: Buffer.from(publicKey).toString('base64') }]))
  const now = Math.floor(Date.now() / 1000)
  const identity = 'cd'.repeat(32)
  const proof = signProof(
    {
      keyId: 'k1',
      issuer: signet,
      identity,
      audience,
      issuedAt: now,
      expiresAt: now + 60,
    },
    secretKey,
  )
  const lines: string[] = []
  const pending = runSignetClient(['--human', signet, audience, keyFile], (line) => lines.push(line))
  try {
    await waitFor(lines, '3. Listening')
    const page = await fetch(audience)
    const html = await page.text()
    expect(html).toContain('location.hash')
    expect(html).toContain('POST')
    const token = Buffer.from(proof).toString('base64url')
    const posted = await fetch(audience, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: `#signet-proof=${token}`,
    })
    expect(posted.status).toBe(204)
    expect(await pending).toBe(0)
    expect(lines[0]).toBe(`1. Signet origin: ${signet}`)
    expect(lines[1]).toBe(`2. Audience: ${audience}`)
    expect(lines[2]).toBe(`3. Listening on ${audience}`)
    expect(lines[3]).toBe(
      `4. Open ${signet}/connect?audience=${encodeURIComponent(audience)}&return=${encodeURIComponent(`${audience}/`)}`,
    )
    expect(lines[4]).toBe(`5. Redirect. Proof bytes: ${proof.byteLength}`)
    expect(lines[5]).toBe(`6. Audience: ${audience}`)
    expect(lines[6]).toMatch(/^7\. Expiry: \d+\. Still valid: yes$/)
    expect(lines[7]).toBe(`8. Identity: ${identity}`)
    expect(lines[7]?.slice('8. Identity: '.length)).toBe(
      verifyProof(proof, {
        issuer: signet,
        audience,
        keys: [{ id: 'k1', publicKey }],
        nowSeconds: now,
      }),
    )
    expect(lines.join('\n')).not.toContain(token)
  } finally {
    await Promise.race([pending, new Promise((resolve) => setTimeout(resolve, 200))])
    await rm(dir, { recursive: true, force: true })
  }
})

it('stops on a human failure fragment and on an audience it cannot hear', async () => {
  const audience = `http://127.0.0.1:${await freePort()}`
  const dir = await mkdtemp(join(tmpdir(), 'signet-client-'))
  const keyFile = join(dir, 'keys.json')
  await writeFile(keyFile, '[]')
  const lines: string[] = []
  const pending = runSignetClient(
    ['--human', 'http://127.0.0.1:8787', audience, keyFile],
    (line) => lines.push(line),
  )
  try {
    await waitFor(lines, '4. Open')
    const posted = await fetch(audience, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: '#signet-identity=failed',
    })
    expect(posted.status).toBe(204)
    expect(await pending).toBe(1)
    expect(lines).toHaveLength(5)
    expect(lines[4]).toBe('5. Redirect. #signet-identity=failed')
    for (const bad of ['https://abc.com', 'https://127.0.0.1:9', 'http://127.0.0.1:9/room']) {
      const heard: string[] = []
      expect(await runSignetClient(['--human', 'http://127.0.0.1:8787', bad, keyFile], (line) => heard.push(line))).toBe(1)
      expect(heard).toEqual([
        '1. Signet origin: http://127.0.0.1:8787',
        `2. Audience: ${bad}. The proof would be returned to that origin.`,
      ])
    }
  } finally {
    await Promise.race([pending, new Promise((resolve) => setTimeout(resolve, 200))])
    await rm(dir, { recursive: true, force: true })
  }
})

function publicFromLog(line: string): Uint8Array {
  const encoded = line.slice('3. Agent key: created. Public key: '.length)
  return new Uint8Array(Buffer.from(encoded, 'base64'))
}
