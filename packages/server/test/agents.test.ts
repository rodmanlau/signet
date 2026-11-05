import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { keygenAsync as generateKeyPair } from '@noble/ed25519'
import { describe, expect, it } from 'vitest'
import { signAgentRequest, verifyProof } from '@agenticage/proof'
import { agentSubject, deriveIdentity } from '../src/identity.js'
import { grantsFilePath } from '../src/grants.js'
import { startLogin, type LoginServerOptions } from '../src/main.js'

const ISSUER = 'https://login.example'
const AUDIENCE = 'http://127.0.0.1:8080'
const NOW = 1_700_000_000
const DERIVATION_KEY = new TextEncoder().encode('test-key')

describe('agent allow and revoke', () => {
  it('returns an approve URL for a signed ticket and rejects a bad signature', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const agent = await generateKeyPair()
    const sessions = await tempSessions()
    const server = await startLogin(loginOptions(sessions.file, secretKey, publicKey))
    try {
      const res = await postTicket(server.url, agent.secretKey, 'Cursor')
      expect(res.status).toBe(200)
      expect(res.headers.get('content-type')).toContain('application/json')
      const body = (await res.json()) as { ticket: string; approveUrl: string; proof?: string }
      expect(body.proof).toBeUndefined()
      expect(body.ticket).toMatch(/^[A-Za-z0-9_-]{16,128}$/)
      expect(body.approveUrl).toBe(`${ISSUER}/agents/approve?ticket=${body.ticket}`)
      await expect(readFile(grantsFilePath(sessions.file), 'utf8')).rejects.toMatchObject({ code: 'ENOENT' })

      const bad = await postTicket(server.url, agent.secretKey, 'Cursor', undefined, (signature) => {
        signature[0] ^= 0xff
      })
      expect(bad.status).toBe(400)
      expect(await bad.text()).toBe('rejected')

      const missingLabel = await fetch(new URL('/agents/ticket', server.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(signedBody(agent.secretKey, NOW, { label: undefined })),
      })
      expect(missingLabel.status).toBe(400)
      const newline = await fetch(new URL('/agents/ticket', server.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(signedBody(agent.secretKey, NOW, { label: 'bad\nname' })),
      })
      expect(newline.status).toBe(400)
      const tooLong = await fetch(new URL('/agents/ticket', server.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(signedBody(agent.secretKey, NOW, { label: 'a'.repeat(201) })),
      })
      expect(tooLong.status).toBe(400)
      expect((await postTicket(server.url, agent.secretKey, 'a'.repeat(200))).status).toBe(200)
      const pathed = signAgentRequest(`${AUDIENCE}/session`, agent.secretKey, NOW)
      const notOrigin = await fetch(new URL('/agents/ticket', server.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          audience: `${AUDIENCE}/session`,
          publicKey: Buffer.from(pathed.publicKey).toString('base64url'),
          issuedAt: NOW,
          signature: Buffer.from(pathed.signature).toString('base64url'),
          label: 'Cursor',
        }),
      })
      expect(notOrigin.status).toBe(400)
      expect(await notOrigin.text()).toBe('rejected')
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('accepts a loopback origin and rejects any other loopback', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const agent = await generateKeyPair()
    const sessions = await tempSessions()
    const server = await startLogin(loginOptions(sessions.file, secretKey, publicKey))
    try {
      for (const loopback of [
        'http://evil.test',
        'http://127.0.0.1:9/steal',
        'http://127.0.0.1:9?x=1',
        'https://127.0.0.1:9',
        'http://127.0.0.1',
        'http://127.1:9',
        'http://0x7f.0.0.1:9',
      ]) {
        const res = await postTicket(server.url, agent.secretKey, 'Cursor', loopback)
        expect(res.status, loopback).toBe(400)
        expect(await res.text()).toBe('rejected')
      }
      for (const loopback of ['http://127.0.0.1:9', 'http://127.0.0.1:9/', 'http://localhost:4317']) {
        const res = await postTicket(server.url, agent.secretKey, 'Cursor', loopback)
        expect(res.status, loopback).toBe(200)
        const body = (await res.json()) as { approveUrl: string }
        expect(body.approveUrl.startsWith(`${ISSUER}/agents/approve?ticket=`)).toBe(true)
      }
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('shows sign-in without a session and an Allow form with one, and does not grant on GET', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const agent = await generateKeyPair()
    const sessions = await tempSessions()
    const server = await startLogin(loginOptions(sessions.file, secretKey, publicKey))
    try {
      const label = '<Cursor>'
      const ticket = await issueTicket(server.url, agent.secretKey, label)
      const missing = await fetch(new URL('/agents/approve', server.url))
      expect(missing.status).toBe(400)
      const approve = new URL(approvePath(ticket), server.url)
      const signedOut = await fetch(approve)
      expect(signedOut.status).toBe(200)
      expect(signedOut.headers.get('content-type')).toContain('text/html')
      const signedOutHtml = await signedOut.text()
      expect(signedOutHtml).toContain(`To authorize an agent labeled &lt;Cursor&gt;, ${fingerprint(agent.publicKey)}, choose an account.`)
      expect(signedOutHtml).not.toContain('<Cursor>')
      expect(signedOutHtml).toContain('<button type="submit">Sign in</button>')
      expect(signedOutHtml).not.toContain('<button type="submit">Allow</button>')
      await expect(readFile(grantsFilePath(sessions.file), 'utf8')).rejects.toMatchObject({ code: 'ENOENT' })

      const cookie = await signIn(server.url, { provider: 'google', subject: 'ada', label: 'Ada' })
      const signedIn = await fetch(approve, { headers: { cookie } })
      expect(signedIn.status).toBe(200)
      const html = await signedIn.text()
      expect(html).toContain(`Allow &lt;Cursor&gt;, ${fingerprint(agent.publicKey)}.`)
      expect(html).toContain(`<form method="post" action="${approvePath(ticket)}"><button type="submit">Allow</button></form>`)
      expect(html).not.toContain('choose an account')
      await expect(readFile(grantsFilePath(sessions.file), 'utf8')).rejects.toMatchObject({ code: 'ENOENT' })

      const anonymous = await fetch(approve, { method: 'POST' })
      expect(anonymous.status).toBe(400)
      expect(await anonymous.text()).toBe('rejected')
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('writes the grant on Allow and then mints an agent proof', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const agent = await generateKeyPair()
    const sessions = await tempSessions()
    const server = await startLogin(loginOptions(sessions.file, secretKey, publicKey))
    try {
      const cookie = await signIn(server.url, { provider: 'google', subject: 'ada', label: 'Ada' })
      const ticket = await issueTicket(server.url, agent.secretKey, 'Cursor')
      const approved = await fetch(new URL(approvePath(ticket), server.url), { method: 'POST', headers: { cookie } })
      expect(approved.status).toBe(200)
      expect(approved.headers.get('location')).toBeNull()
      expect(await approved.text()).toContain('Allowed Cursor.')
      const wire = Buffer.from(agent.publicKey).toString('base64url')
      expect(JSON.parse(await readFile(grantsFilePath(sessions.file), 'utf8'))).toEqual([
        {
          ownerProvider: 'google',
          ownerSubject: 'ada',
          publicKey: wire,
          label: 'Cursor',
          createdAt: NOW,
        },
      ])
      expect(await readFile(sessions.file, 'utf8')).not.toContain(wire)
      const proof = await postAgentProof(server.url, agent.secretKey)
      expect(proof.status).toBe(200)
      const parsed = (await proof.json()) as { proof: string }
      expect(acceptedIdentity(Buffer.from(parsed.proof, 'base64url'), publicKey)).toBe(
        deriveIdentity('agent', agentSubject(agent.publicKey), '127.0.0.1', DERIVATION_KEY),
      )
      const spent = await fetch(new URL(approvePath(ticket), server.url), { headers: { cookie } })
      expect(spent.status).toBe(400)
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('redirects Allow to the loopback origin with #signet-agent=allowed', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const agent = await generateKeyPair()
    const sessions = await tempSessions()
    const server = await startLogin(loginOptions(sessions.file, secretKey, publicKey))
    try {
      const cookie = await signIn(server.url, { provider: 'google', subject: 'ada', label: 'Ada' })
      const ticket = await issueTicket(server.url, agent.secretKey, 'Cursor', 'http://127.0.0.1:9')
      const approved = await fetch(new URL(approvePath(ticket), server.url), {
        method: 'POST',
        redirect: 'manual',
        headers: { cookie },
      })
      expect(approved.status).toBe(303)
      expect(approved.headers.get('location')).toBe('http://127.0.0.1:9/#signet-agent=allowed')
      expect(await postAgentProof(server.url, agent.secretKey)).toMatchObject({ status: 200 })
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('refuses a second owner who tries to take the same public key', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const agent = await generateKeyPair()
    const sessions = await tempSessions()
    const server = await startLogin(loginOptions(sessions.file, secretKey, publicKey))
    try {
      const ada = await signIn(server.url, { provider: 'google', subject: 'ada', label: 'Ada' })
      const first = await issueTicket(server.url, agent.secretKey, 'Cursor')
      expect((await fetch(new URL(approvePath(first), server.url), { method: 'POST', headers: { cookie: ada } })).status).toBe(200)
      const bea = await signIn(server.url, { provider: 'apple', subject: 'bea', label: 'Bea' })
      const second = await issueTicket(server.url, agent.secretKey, 'Stolen')
      const stolen = await fetch(new URL(approvePath(second), server.url), { method: 'POST', headers: { cookie: bea } })
      expect(stolen.status).toBe(409)
      expect(await stolen.text()).toBe('already allowed')
      expect(JSON.parse(await readFile(grantsFilePath(sessions.file), 'utf8'))).toEqual([
        {
          ownerProvider: 'google',
          ownerSubject: 'ada',
          publicKey: Buffer.from(agent.publicKey).toString('base64url'),
          label: 'Cursor',
          createdAt: NOW,
        },
      ])
      expect((await postAgentProof(server.url, agent.secretKey)).status).toBe(200)
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('lists only the signed-in owner and revoke removes that grant', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const adaKey = await generateKeyPair()
    const beaKey = await generateKeyPair()
    const sessions = await tempSessions()
    const server = await startLogin(loginOptions(sessions.file, secretKey, publicKey))
    try {
      const ada = await signIn(server.url, { provider: 'google', subject: 'ada', label: 'Ada' })
      const bea = await signIn(server.url, { provider: 'apple', subject: 'bea', label: 'Bea' })
      const cleo = await signIn(server.url, { provider: 'facebook', subject: 'cleo', label: 'Cleo' })
      const adaTicket = await issueTicket(server.url, adaKey.secretKey, 'Cursor ada')
      const beaTicket = await issueTicket(server.url, beaKey.secretKey, 'Cursor bea')
      expect((await fetch(new URL(approvePath(adaTicket), server.url), { method: 'POST', headers: { cookie: ada } })).status).toBe(200)
      expect((await fetch(new URL(approvePath(beaTicket), server.url), { method: 'POST', headers: { cookie: bea } })).status).toBe(200)

      const adaPage = await fetch(new URL('/agents', server.url), { headers: { cookie: ada } })
      expect(adaPage.status).toBe(200)
      const adaHtml = await adaPage.text()
      expect(adaHtml).toContain('Cursor ada')
      expect(adaHtml).toContain(fingerprint(adaKey.publicKey))
      expect(adaHtml).toContain(`<time>${NOW}</time>`)
      expect(adaHtml).toContain(Buffer.from(adaKey.publicKey).toString('base64url'))
      expect(adaHtml).not.toContain('Cursor bea')
      expect(adaHtml).not.toContain(fingerprint(beaKey.publicKey))
      const beaHtml = await (await fetch(new URL('/agents', server.url), { headers: { cookie: bea } })).text()
      expect(beaHtml).toContain('Cursor bea')
      expect(beaHtml).not.toContain('Cursor ada')
      const cleoHtml = await (await fetch(new URL('/agents', server.url), { headers: { cookie: cleo } })).text()
      expect(cleoHtml).toContain('No agents.')
      expect(cleoHtml).not.toContain('Cursor ada')
      expect(cleoHtml).not.toContain('Cursor bea')

      const blocked = await fetch(new URL('/agents/revoke', server.url), {
        method: 'POST',
        redirect: 'manual',
        headers: { cookie: bea, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ publicKey: Buffer.from(adaKey.publicKey).toString('base64url') }).toString(),
      })
      expect(blocked.status).toBe(303)
      expect(blocked.headers.get('location')).toBe('/agents')
      expect((await postAgentProof(server.url, adaKey.secretKey)).status).toBe(200)

      const revoked = await fetch(new URL('/agents/revoke', server.url), {
        method: 'POST',
        redirect: 'manual',
        headers: { cookie: ada, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ publicKey: Buffer.from(adaKey.publicKey).toString('base64url') }).toString(),
      })
      expect(revoked.status).toBe(303)
      expect(revoked.headers.get('location')).toBe('/agents')
      const denied = await postAgentProof(server.url, adaKey.secretKey)
      expect(denied.status).toBe(403)
      expect(await denied.json()).toEqual({ error: 'unauthorized', skill: `${ISSUER}/agents/skill` })
      expect((await postAgentProof(server.url, beaKey.secretKey)).status).toBe(200)
      const jsonRevoke = await fetch(new URL('/agents/revoke', server.url), {
        method: 'POST',
        redirect: 'manual',
        headers: { cookie: bea, 'content-type': 'application/json' },
        body: JSON.stringify({ publicKey: Buffer.from(beaKey.publicKey).toString('base64url') }),
      })
      expect(jsonRevoke.status).toBe(303)
      expect(jsonRevoke.headers.get('location')).toBe('/agents')
      const beaDenied = await postAgentProof(server.url, beaKey.secretKey)
      expect(beaDenied.status).toBe(403)
      const after = await (await fetch(new URL('/agents', server.url), { headers: { cookie: ada } })).text()
      expect(after).not.toContain('Cursor ada')
      expect(after).toContain('No agents.')
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('serves the authorize skill as markdown', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const sessions = await tempSessions()
    const server = await startLogin(loginOptions(sessions.file, secretKey, publicKey))
    try {
      const res = await fetch(new URL('/agents/skill', server.url))
      expect(res.status).toBe(200)
      expect(res.headers.get('content-type')).toContain('text/markdown')
      const text = await res.text()
      expect(text).toContain('/agents/ticket')
      expect(text).toContain('approveUrl')
      expect(text).toContain('poll')
      expect(text).toContain('/agents')
      expect(text).toContain('#signet-agent=allowed')
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('returns test-login from the approve page onto that page with a session', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const agent = await generateKeyPair()
    const sessions = await tempSessions()
    const server = await startLogin(loginOptions(sessions.file, secretKey, publicKey))
    try {
      const ticket = await issueTicket(server.url, agent.secretKey, 'Cursor')
      const page = await fetch(new URL(approvePath(ticket), server.url))
      const html = await page.text()
      const action = html.match(/action="([^"]+)"/)?.[1]?.replaceAll('&amp;', '&') ?? ''
      expect(action.startsWith('/test-login?next=')).toBe(true)
      const posted = await fetch(new URL(action, server.url), {
        method: 'POST',
        redirect: 'manual',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: '',
      })
      expect(posted.status).toBe(303)
      const location = new URL(posted.headers.get('location') ?? '')
      expect(location.origin).toBe(ISSUER)
      expect(location.pathname).toBe('/agents/approve')
      expect(location.searchParams.get('ticket')).toBe(ticket)
      expect(location.hash).not.toContain('signet-proof')
      expect(await posted.text()).not.toContain('signet-proof')
      const cookie = `valar_session=${cookieValue(setCookie(posted, 'valar_session'))}`
      const allow = await fetch(new URL(`${location.pathname}${location.search}`, server.url), { headers: { cookie } })
      expect(allow.status).toBe(200)
      const allowHtml = await allow.text()
      expect(allowHtml).toContain('<button type="submit">Allow</button>')
      expect(allowHtml).toContain('Cursor')
      expect(allowHtml).not.toContain('choose an account')

      const evil = new URL('/test-login', server.url)
      evil.searchParams.set('next', 'http://evil.test/agents')
      const refused = await fetch(evil, { method: 'POST', redirect: 'manual', body: '' })
      expect(refused.status).toBe(400)
      expect(refused.headers.getSetCookie().some((line) => line.startsWith('valar_session='))).toBe(false)

      const home = await fetch(new URL('/agents', server.url))
      const homeHtml = await home.text()
      const homeAction = homeHtml.match(/action="([^"]+)"/)?.[1]?.replaceAll('&amp;', '&') ?? ''
      expect(homeAction).toBe('/test-login?next=%2Fagents')
      const back = await fetch(new URL(homeAction, server.url), { method: 'POST', redirect: 'manual', body: '' })
      expect(back.status).toBe(303)
      expect(back.headers.get('location')).toBe(`${ISSUER}/agents`)
      const listed = await fetch(new URL('/agents', server.url), {
        headers: { cookie: `valar_session=${cookieValue(setCookie(back, 'valar_session'))}` },
      })
      expect(await listed.text()).toContain('<h1>Agents</h1>')
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('returns OAuth from the approve page without minting a site proof', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const agent = await generateKeyPair()
    const sessions = await tempSessions()
    const server = await startLogin(
      loginOptions(sessions.file, secretKey, publicKey, {
        testLogin: false,
        providers: {
          google: {
            clientId: 'google-client',
            authorizeUrl: 'https://provider.test/auth',
            exchange: async () => ({ subject: 'ada', label: 'Ada' }),
          },
        },
      }),
    )
    try {
      const ticket = await issueTicket(server.url, agent.secretKey, 'Cursor')
      const page = await fetch(new URL(approvePath(ticket), server.url))
      const html = await page.text()
      expect(html).toContain('/auth/google?next=')
      expect(html).not.toContain('audience=')
      const href = html.match(/href="(\/auth\/google\?[^"]+)"/)?.[1]?.replaceAll('&amp;', '&') ?? ''
      const began = await fetch(new URL(href, server.url), { redirect: 'manual' })
      expect(began.status).toBe(302)
      const state = new URL(began.headers.get('location') ?? '').searchParams.get('state')
      const nonce = cookieValue(setCookie(began, 'valar_oauth'))
      const callback = new URL('/auth/google/callback', server.url)
      callback.searchParams.set('code', 'code-1')
      callback.searchParams.set('state', state ?? '')
      const back = await fetch(callback, { redirect: 'manual', headers: { cookie: `valar_oauth=${nonce}` } })
      expect(back.status).toBe(303)
      const location = new URL(back.headers.get('location') ?? '')
      expect(location.origin).toBe(ISSUER)
      expect(location.pathname).toBe('/agents/approve')
      expect(location.searchParams.get('ticket')).toBe(ticket)
      expect(location.hash).not.toContain('signet-proof')
      expect(await back.text()).not.toContain('signet-proof')
      const cookie = `valar_session=${cookieValue(setCookie(back, 'valar_session'))}`
      const allow = await fetch(new URL(`${location.pathname}${location.search}`, server.url), { headers: { cookie } })
      expect(await allow.text()).toContain('<button type="submit">Allow</button>')

      for (const next of [
        'https://evil.test/agents',
        '//evil.test/agents',
        '/connect',
        '/agents/../connect',
        'https://login.example/connect',
        'https://user:pass@login.example/agents',
        '/\\evil.test/agents',
      ]) {
        const url = new URL('/auth/google', server.url)
        url.searchParams.set('next', next)
        const refused = await fetch(url, { redirect: 'manual' })
        expect(refused.status, next).toBe(400)
        expect(refused.headers.get('location')).toBeNull()
      }
      const both = new URL('/auth/google', server.url)
      both.searchParams.set('next', '/agents')
      both.searchParams.set('audience', AUDIENCE)
      both.searchParams.set('return', `${AUDIENCE}/`)
      expect((await fetch(both, { redirect: 'manual' })).status).toBe(400)
      const absolute = new URL('/auth/google', server.url)
      absolute.searchParams.set('next', `${ISSUER}/agents`)
      expect((await fetch(absolute, { redirect: 'manual' })).status).toBe(302)
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('drops an approve ticket after ten minutes', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const agent = await generateKeyPair()
    const sessions = await tempSessions()
    let now = NOW
    const server = await startLogin(loginOptions(sessions.file, secretKey, publicKey, { now: () => now }))
    try {
      const ticket = await issueTicket(server.url, agent.secretKey, 'Cursor')
      now = NOW + 599
      expect((await fetch(new URL(approvePath(ticket), server.url))).status).toBe(200)
      now = NOW + 600
      const expired = await fetch(new URL(approvePath(ticket), server.url))
      expect(expired.status).toBe(400)
      expect(await expired.text()).toBe('rejected')
    } finally {
      await server.close()
      await sessions.remove()
    }
  })
})

function loginOptions(
  sessionsFile: string,
  secretKey: Uint8Array,
  publicKey: Uint8Array,
  extra?: Partial<LoginServerOptions>,
): LoginServerOptions {
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
    ...extra,
  }
}

function signedBody(
  secretKey: Uint8Array,
  issuedAt: number,
  extra: { label?: string; loopback?: string },
  mutate?: (signature: Uint8Array) => void,
): Record<string, unknown> {
  const signed = signAgentRequest(AUDIENCE, secretKey, issuedAt)
  const signature = Uint8Array.from(signed.signature)
  mutate?.(signature)
  const body: Record<string, unknown> = {
    audience: AUDIENCE,
    publicKey: Buffer.from(signed.publicKey).toString('base64url'),
    issuedAt,
    signature: Buffer.from(signature).toString('base64url'),
  }
  if (extra.label !== undefined) body.label = extra.label
  if (extra.loopback !== undefined) body.loopback = extra.loopback
  return body
}

function postTicket(
  origin: string,
  secretKey: Uint8Array,
  label: string,
  loopback?: string,
  mutate?: (signature: Uint8Array) => void,
): Promise<Response> {
  return fetch(new URL('/agents/ticket', origin), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(signedBody(secretKey, NOW, { label, loopback }, mutate)),
  })
}

async function issueTicket(origin: string, secretKey: Uint8Array, label: string, loopback?: string): Promise<string> {
  const res = await postTicket(origin, secretKey, label, loopback)
  expect(res.status).toBe(200)
  const body = (await res.json()) as { ticket: string }
  return body.ticket
}

function approvePath(ticket: string): string {
  return `/agents/approve?ticket=${encodeURIComponent(ticket)}`
}

function fingerprint(publicKey: Uint8Array): string {
  const hex = Buffer.from(publicKey).toString('hex')
  return `${hex.slice(0, 8)}...${hex.slice(-8)}`
}

async function postAgentProof(origin: string, secretKey: Uint8Array): Promise<Response> {
  return fetch(new URL('/agent-proof', origin), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(signedBody(secretKey, NOW, {})),
  })
}

function acceptedIdentity(proof: Uint8Array, publicKey: Uint8Array): string {
  return verifyProof(proof, {
    issuer: ISSUER,
    audience: AUDIENCE,
    keys: [{ id: 'k1', publicKey }],
    nowSeconds: NOW,
  })
}

async function signIn(
  origin: string,
  session: { provider: 'google' | 'apple' | 'facebook'; subject: string; label: string },
): Promise<string> {
  const res = await fetch(new URL('/test-login', origin), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(session),
  })
  expect(res.status).toBe(204)
  return `valar_session=${cookieValue(setCookie(res, 'valar_session'))}`
}

function setCookie(res: Response, name: string): string {
  const line = res.headers.getSetCookie().find((item) => item.startsWith(`${name}=`))
  expect(line, name).toBeTruthy()
  return line ?? ''
}

function cookieValue(line: string): string {
  return line.slice(line.indexOf('=') + 1).split(';')[0] ?? ''
}

async function tempSessions(): Promise<{ file: string; remove(): Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), 'valar-agents-'))
  return {
    file: join(dir, 'sessions.json'),
    async remove() {
      await rm(dir, { recursive: true, force: true })
    },
  }
}
