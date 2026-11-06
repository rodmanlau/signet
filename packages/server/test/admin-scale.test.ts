import { readFileSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { keygenAsync as generateKeyPair } from '@noble/ed25519'
import { describe, expect, it } from 'vitest'
import { signAgentRequest } from '@agenticage/proof'
import { startLogin, type LoginServerOptions } from '../src/main.js'

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..')
const scaleDoc = readFileSync(join(root, 'docs/admin-scale.md'), 'utf8')
const adminDoc = readFileSync(join(root, 'docs/admin.md'), 'utf8')

const ISSUER = 'https://login.example'
const AUDIENCE = 'http://127.0.0.1:8080'
const NOW = 1_700_000_000
const DERIVATION_KEY = new TextEncoder().encode('test-key')

describe('scale guide thresholds', () => {
  it('keeps the stay numbers and the T1 through T5 actions', () => {
    const stay = scaleDoc.slice(0, scaleDoc.indexOf('## Triggers'))
    expect(stay).toContain('## Stay on one machine')
    expect(stay).toMatch(/under about 10 requests per second/)
    expect(stay).toMatch(/under 100ms/)
    expect(stay).toMatch(/under 1 proof per second/i)
    expect(stay).toMatch(/stay on one machine/)
    expect(stay).toMatch(/one Signet machine/)
    expect(stay).toMatch(/Managed Postgres Basic/)
    expect(stay).toMatch(/under 50%/)
    expect(stay).toMatch(/`iad`/)

    const triggers = section(scaleDoc, '## Triggers', '## Read the signals')
    expect(triggerRow(triggers, 'T1')).toMatch(/machine/i)
    expect(triggerRow(triggers, 'T1')).toMatch(/Redis/)
    expect(triggerRow(triggers, 'T2')).toMatch(/pool/i)
    expect(triggerRow(triggers, 'T3')).toMatch(/latency/i)
    expect(triggerRow(triggers, 'T3')).toMatch(/over 100ms/)
    expect(triggerRow(triggers, 'T3')).toMatch(/over 300ms/)
    expect(triggerRow(triggers, 'T4')).toMatch(/ticket/i)
    expect(triggerRow(triggers, 'T4')).toMatch(/Redis/)
    expect(triggerRow(triggers, 'T5')).toMatch(/cache/i)
    expect(triggerRow(triggers, 'T6')).toMatch(/region/i)

    expect(adminDoc).toContain('](admin-scale.md)')
  })
})

describe('GET /metrics', () => {
  it('counts one unauthorized proof and then ten granted proofs', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const agent = await generateKeyPair()
    const sessions = await tempSessions()
    const server = await startLogin(loginOptions(sessions.file, secretKey, publicKey))
    try {
      expect(await readMetrics(server.url)).toEqual({ granted: 0, unauthorized: 0 })

      const denied = await postAgentProof(server.url, agent.secretKey)
      expect(denied.status).toBe(403)
      expect(await denied.json()).toMatchObject({ error: 'unauthorized' })
      expect(await readMetrics(server.url)).toEqual({ granted: 0, unauthorized: 1 })

      const rejected = await postAgentProof(server.url, agent.secretKey, (signature) => {
        signature[0] ^= 0xff
      })
      expect(rejected.status).toBe(400)
      expect(await readMetrics(server.url)).toEqual({ granted: 0, unauthorized: 1 })

      const cookie = await signIn(server.url)
      const ticket = await issueTicket(server.url, agent.secretKey)
      const approved = await fetch(new URL(`/agents/approve?ticket=${encodeURIComponent(ticket)}`, server.url), {
        method: 'POST',
        headers: { cookie },
      })
      expect(approved.status).toBe(200)

      for (let n = 0; n < 10; n += 1) {
        const proof = await postAgentProof(server.url, agent.secretKey)
        expect(proof.status).toBe(200)
      }
      expect(await readMetrics(server.url)).toEqual({ granted: 10, unauthorized: 1 })
    } finally {
      await server.close()
      await sessions.remove()
    }
  })
})

function section(doc: string, start: string, end: string): string {
  const from = doc.indexOf(start)
  const to = doc.indexOf(end)
  expect(from).toBeGreaterThanOrEqual(0)
  expect(to).toBeGreaterThan(from)
  return doc.slice(from, to)
}

function triggerRow(doc: string, id: string): string {
  const line = doc.split('\n').find((row) => row.startsWith(`| ${id} |`))
  expect(line, id).toBeTruthy()
  return line ?? ''
}

function loginOptions(sessionsFile: string, secretKey: Uint8Array, publicKey: Uint8Array): LoginServerOptions {
  return {
    port: 0,
    issuer: ISSUER,
    keyId: 'k1',
    privateKey: secretKey,
    publicKey,
    derivationKey: DERIVATION_KEY,
    now: () => NOW,
    testLogin: true,
    providers: {},
    sessionsFile,
    databaseUrl: '',
  }
}

function signedBody(secretKey: Uint8Array, mutate?: (signature: Uint8Array) => void): Record<string, unknown> {
  const signed = signAgentRequest(AUDIENCE, secretKey, NOW)
  const signature = Uint8Array.from(signed.signature)
  mutate?.(signature)
  return {
    audience: AUDIENCE,
    publicKey: Buffer.from(signed.publicKey).toString('base64url'),
    issuedAt: NOW,
    signature: Buffer.from(signature).toString('base64url'),
  }
}

function postAgentProof(
  origin: string,
  secretKey: Uint8Array,
  mutate?: (signature: Uint8Array) => void,
): Promise<Response> {
  return fetch(new URL('/agent-proof', origin), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(signedBody(secretKey, mutate)),
  })
}

async function issueTicket(origin: string, secretKey: Uint8Array): Promise<string> {
  const res = await fetch(new URL('/agents/ticket', origin), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ...signedBody(secretKey), label: 'Cursor' }),
  })
  expect(res.status).toBe(200)
  const body = (await res.json()) as { ticket: string }
  return body.ticket
}

async function signIn(origin: string): Promise<string> {
  const res = await fetch(new URL('/test-login', origin), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ provider: 'google', subject: 'ada', label: 'Ada' }),
  })
  expect(res.status).toBe(204)
  const line = res.headers.getSetCookie().find((item) => item.startsWith('valar_session='))
  expect(line).toBeTruthy()
  const value = (line ?? '').slice('valar_session='.length).split(';')[0] ?? ''
  return `valar_session=${value}`
}

async function readMetrics(origin: string): Promise<{ granted: number; unauthorized: number }> {
  const res = await fetch(new URL('/metrics', origin))
  expect(res.status).toBe(200)
  expect(res.headers.get('content-type')).toContain('text/plain')
  const text = await res.text()
  const granted = metric(text, 'signet_agent_proof_total')
  const unauthorized = metric(text, 'signet_agent_proof_unauthorized_total')
  expect(text).toBe(`signet_agent_proof_total ${granted}\nsignet_agent_proof_unauthorized_total ${unauthorized}\n`)
  return { granted, unauthorized }
}

function metric(text: string, name: string): number {
  const line = text.split('\n').find((item) => item.startsWith(`${name} `))
  expect(line, name).toBeTruthy()
  return Number((line ?? '').slice(name.length + 1))
}

async function tempSessions(): Promise<{ file: string; remove(): Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), 'signet-metrics-'))
  return {
    file: join(dir, 'sessions.json'),
    async remove() {
      await rm(dir, { recursive: true, force: true })
    },
  }
}
