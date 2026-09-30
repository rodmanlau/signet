// @noble/ed25519 exports keygenAsync, not generateKeyPair. Same { secretKey, publicKey } shape.
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { keygenAsync as generateKeyPair } from '@noble/ed25519'
import { describe, expect, it } from 'vitest'
import { readProofAudience, readProofExpiry, signAgentRequest, verifyProof } from '@agenticage/proof'
import { agentSubject, deriveIdentity } from '../src/identity.js'
import { connectingText, decideAgentProof, decideConnect } from '../src/connect.js'
import { startLogin } from '../src/main.js'

function acceptedIdentity(
  proof: Uint8Array,
  publicKey: Uint8Array,
  nowSeconds: number,
  issuer: string,
  audience: string,
): string {
  return verifyProof(proof, {
    issuer,
    audience,
    keys: [{ id: 'k1', publicKey }],
    nowSeconds,
  })
}

describe('decideConnect', () => {
  it('refuses a return origin that is not the audience', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const keys = {
      issuer: 'https://login.example',
      keyId: 'k1',
      privateKey: secretKey,
      derivationKey: new TextEncoder().encode('test-key'),
      now: 1_700_000_000,
    }
    const session = { provider: 'google' as const, subject: 'sub-1', label: 'ada@gmail.com' }
    expect(
      decideConnect({ ...keys, session, audience: 'https://friends.example', returnUrl: 'https://evil.example/room' }).type,
    ).toBe('reject')
    expect(
      decideConnect({
        ...keys,
        privateKey: Uint8Array.of(1),
        session,
        audience: 'https://friends.example',
        returnUrl: 'https://evil.example/room',
      }).type,
    ).toBe('reject')
    expect(
      decideConnect({ ...keys, session, audience: 'https://friends.example', returnUrl: 'not a url' }).type,
    ).toBe('reject')
    expect(
      decideConnect({ ...keys, session, audience: 'https://friends.example', returnUrl: 'javascript:alert(1)' }).type,
    ).toBe('reject')
    expect(
      decideConnect({
        ...keys,
        session,
        audience: 'https://friends.example',
        returnUrl: 'https://friends.example.evil.com/room',
      }).type,
    ).toBe('reject')
    expect(
      decideConnect({
        ...keys,
        session,
        audience: 'https://friends.example',
        returnUrl: 'https://friends.example:444/room',
      }).type,
    ).toBe('reject')
    expect(
      decideConnect({ ...keys, session, audience: 'https://friends.example', returnUrl: 'http://friends.example/room' }).type,
    ).toBe('reject')
    const ok = decideConnect({
      ...keys,
      session,
      audience: 'https://friends.example',
      returnUrl: 'https://friends.example/room?x=1#keep',
    })
    expect(ok.type).toBe('redirect')
    if (ok.type !== 'redirect') return
    expect(ok.location.startsWith('https://friends.example/room?x=1#signet-proof=')).toBe(true)
    expect(ok.location).not.toContain('keep')
    const encoded = new URL(ok.location).hash.slice('#signet-proof='.length)
    expect(encoded).not.toContain('=')
    const proof = Buffer.from(encoded, 'base64url')
    expect(readProofAudience(proof)).toBe('https://friends.example')
    const identity = acceptedIdentity(proof, publicKey, keys.now, keys.issuer, 'https://friends.example')
    expect(identity).toHaveLength(64)
    expect(identity).toBe(deriveIdentity('google', 'sub-1', 'friends.example', keys.derivationKey))
    expect(readProofExpiry(proof)).toBe(keys.now + 15 * 60)
    expect(() =>
      acceptedIdentity(proof, publicKey, keys.now + 15 * 60 + 61, keys.issuer, 'https://friends.example'),
    ).toThrow(/bad_proof/)
    const otherKey = new TextEncoder().encode('other-key')
    const other = decideConnect({
      ...keys,
      derivationKey: otherKey,
      session,
      audience: 'https://friends.example',
      returnUrl: 'https://friends.example/room',
    })
    expect(other.type).toBe('redirect')
    if (other.type !== 'redirect') return
    const otherProof = Buffer.from(new URL(other.location).hash.slice('#signet-proof='.length), 'base64url')
    const otherIdentity = acceptedIdentity(otherProof, publicKey, keys.now, keys.issuer, 'https://friends.example')
    expect(otherIdentity).toBe(deriveIdentity('google', 'sub-1', 'friends.example', otherKey))
    expect(otherIdentity).not.toBe(identity)
    const local = decideConnect({
      ...keys,
      session,
      audience: 'http://127.0.0.1:8080',
      returnUrl: 'http://127.0.0.1:8080/room',
    })
    expect(local.type).toBe('redirect')
    if (local.type !== 'redirect') return
    const localProof = Buffer.from(new URL(local.location).hash.slice('#signet-proof='.length), 'base64url')
    expect(readProofAudience(localProof)).toBe('http://127.0.0.1:8080')
    expect(acceptedIdentity(localProof, publicKey, keys.now, keys.issuer, 'http://127.0.0.1:8080')).toBe(
      deriveIdentity('google', 'sub-1', '127.0.0.1', keys.derivationKey),
    )
    expect(
      decideConnect({
        ...keys,
        session,
        audience: 'http://127.0.0.1:8080',
        returnUrl: 'http://127.0.0.1:3000/room',
      }).type,
    ).toBe('reject')
    expect(connectingText('https://friends.example', 'ada@gmail.com')).toBe(
      'Connecting to https://friends.example as ada@gmail.com',
    )
    expect(connectingText('https://friends.example', 'ada@gmail.com', 'Friends')).toBe(
      'Connecting to https://friends.example (Friends) as ada@gmail.com',
    )
    expect(
      decideConnect({ ...keys, session: null, audience: 'https://friends.example', returnUrl: 'https://friends.example/room' })
        .type,
    ).toBe('providers')
  })
})

describe('login origin', () => {
  it('shows configured providers and signs only the stub subject', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const derivationKey = new TextEncoder().encode('0123456789abcdef0123456789abcdef')
    const issuer = 'https://login.example'
    const audience = 'https://friends.example'
    const returnUrl = 'https://friends.example/room'
    let calls = 0
    const sessions = await tempSessions()
    const server = await startLogin({
      port: 0,
      issuer,
      keyId: 'k1',
      privateKey: secretKey,
      publicKey,
      derivationKey,
      now: () => 1_700_000_000,
      testLogin: false,
      sessionsFile: sessions.file,
      providers: {
        google: {
          clientId: 'google-client',
          authorizeUrl: 'https://provider.test/auth',
          exchange: async (code) => {
            calls += 1
            if (code === 'bad') throw new Error('provider down')
            return { subject: 'sub-from-provider', label: 'ada@gmail.com' }
          },
        },
      },
    })
    try {
      const oldKeys = await fetch(new URL('/.well-known/valar-keys', server.url))
      expect(oldKeys.status).toBe(404)
      const keys = await fetch(new URL('/.well-known/signet-keys', server.url))
      expect(keys.status).toBe(200)
      expect(await keys.json()).toEqual({
        keys: [{ id: 'k1', publicKey: Buffer.from(publicKey).toString('base64') }],
      })

      const hidden = await fetch(new URL('/test-login', server.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ provider: 'google', subject: 'attacker', label: 'attacker' }),
      })
      expect(hidden.status).toBe(404)

      const connect = new URL('/connect', server.url)
      connect.searchParams.set('audience', audience)
      connect.searchParams.set('return', returnUrl)
      connect.searchParams.set('site', 'Friends')
      const page = await fetch(connect)
      expect(page.status).toBe(200)
      const html = await page.text()
      expect(html).toContain('/auth/google?')
      expect(html).not.toContain('/auth/apple')
      expect(html).not.toContain('/auth/facebook')
      expect(html).not.toContain('/test-login')

      const evil = new URL('/connect', server.url)
      evil.searchParams.set('audience', audience)
      evil.searchParams.set('return', 'https://evil.example/room')
      const rejected = await fetch(evil, { redirect: 'manual' })
      expect(rejected.status).toBe(400)
      expect(rejected.headers.get('location')).toBeNull()

      const badStart = new URL('/auth/google', server.url)
      badStart.searchParams.set('audience', audience)
      badStart.searchParams.set('return', 'https://evil.example/room')
      const refused = await fetch(badStart, { redirect: 'manual' })
      expect(refused.status).toBe(400)
      expect(refused.headers.get('location')).toBeNull()

      const missing = new URL('/auth/apple', server.url)
      missing.searchParams.set('audience', audience)
      missing.searchParams.set('return', returnUrl)
      expect((await fetch(missing, { redirect: 'manual' })).status).toBe(404)

      const began = await fetch(authUrl(server.url, audience, returnUrl, 'Friends'), { redirect: 'manual' })
      expect(began.status).toBe(302)
      const authorize = new URL(began.headers.get('location') ?? '')
      expect(authorize.origin).toBe('https://provider.test')
      expect(authorize.searchParams.get('client_id')).toBe('google-client')
      expect(authorize.searchParams.get('redirect_uri')).toBe('https://login.example/auth/google/callback')
      const state = authorize.searchParams.get('state')
      expect(state).toBeTruthy()
      const nonce = cookieValue(setCookie(began, 'valar_oauth'))

      const callback = new URL('/auth/google/callback', server.url)
      callback.searchParams.set('code', 'code-1')
      callback.searchParams.set('state', state ?? '')
      callback.searchParams.set('subject', 'attacker')
      callback.searchParams.set('label', 'attacker')
      const back = await fetch(callback, { redirect: 'manual', headers: { cookie: `valar_oauth=${nonce}` } })
      expect(calls).toBe(1)
      expect(back.status).toBe(200)
      expect(back.headers.get('location')).toBeNull()
      const backBody = await back.text()
      expect(backBody).toContain('Connecting to https://friends.example (Friends) as ada@gmail.com')
      const sessionLine = setCookie(back, 'valar_session')
      expect(sessionLine).toContain('HttpOnly')
      expect(sessionLine).toContain('Secure')
      expect(sessionLine).toContain('SameSite=Lax')
      expect(sessionLine).toContain('Max-Age=34560000')
      expect(sessionLine).not.toMatch(/Expires=/i)
      const session = cookieValue(sessionLine)
      const proof = proofFromPage(backBody)
      expect(readProofAudience(proof)).toBe(audience)
      expect(acceptedIdentity(proof, publicKey, 1_700_000_000, issuer, audience)).toBe(
        deriveIdentity('google', 'sub-from-provider', 'friends.example', derivationKey),
      )
      expect(readProofExpiry(proof)).toBe(1_700_000_000 + 15 * 60)

      const done = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${session}` } })
      expect(done.status).toBe(200)
      const doneBody = await done.text()
      expect(doneBody).toContain('Connecting to https://friends.example (Friends) as ada@gmail.com')
      expect(proofFromPage(doneBody).length).toBeGreaterThan(0)
      const kept = setCookie(done, 'valar_session')
      expect(kept).toContain('Max-Age=34560000')
      expect(cookieValue(kept)).toBe(session)

      const again = await fetch(authUrl(server.url, audience, returnUrl), { redirect: 'manual' })
      const againState = new URL(again.headers.get('location') ?? '').searchParams.get('state')
      const againNonce = cookieValue(setCookie(again, 'valar_oauth'))
      const failedCallback = new URL('/auth/google/callback', server.url)
      failedCallback.searchParams.set('code', 'bad')
      failedCallback.searchParams.set('state', againState ?? '')
      const failed = await fetch(failedCallback, {
        redirect: 'manual',
        headers: { cookie: `valar_oauth=${againNonce}` },
      })
      expect(calls).toBe(2)
      expect(failed.status).toBe(303)
      const failure = new URL(failed.headers.get('location') ?? '')
      expect(failure.origin).toBe(audience)
      expect(failure.hash).toBe('#signet-identity=failed')
      expect(failure.hash).not.toContain('valar-proof')
      expect(failed.headers.getSetCookie().some((line) => /^valar_session=[^;]/.test(line))).toBe(false)

      const loggedOut = await fetch(new URL('/logout', server.url), {
        method: 'POST',
        redirect: 'manual',
        headers: { cookie: `valar_session=${session}` },
      })
      expect(loggedOut.status).toBe(204)
      const cleared = setCookie(loggedOut, 'valar_session')
      expect(cleared).toContain('HttpOnly')
      expect(cleared).toContain('Secure')
      expect(cleared).toContain('SameSite=Lax')
      expect(cleared).toContain('Max-Age=0')
      const after = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${session}` } })
      expect(after.status).toBe(200)
      expect(await after.text()).toContain('/auth/google?')
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('mints a session from test-login only when that route is enabled', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const derivationKey = new TextEncoder().encode('fedcba9876543210fedcba9876543210')
    const sessions = await tempSessions()
    const server = await startLogin({
      port: 0,
      issuer: 'https://login.example',
      keyId: 'k1',
      privateKey: secretKey,
      publicKey,
      derivationKey,
      now: () => 1_700_000_000,
      testLogin: true,
      providers: {},
      sessionsFile: sessions.file,
    })
    try {
      const res = await fetch(new URL('/test-login', server.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ provider: 'apple', subject: 'sub-9', label: 'Ada' }),
      })
      expect(res.status).toBe(204)
      const line = setCookie(res, 'valar_session')
      expect(line).toContain('HttpOnly')
      expect(line).toContain('Secure')
      expect(line).toContain('SameSite=Lax')
      expect(line).toContain('Max-Age=34560000')
      expect(line).not.toMatch(/Expires=/i)
      const connect = new URL('/connect', server.url)
      connect.searchParams.set('audience', 'https://friends.example')
      connect.searchParams.set('return', 'https://friends.example/room')
      const done = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${cookieValue(line)}` } })
      expect(done.status).toBe(200)
      const body = await done.text()
      expect(body).toContain('Connecting to https://friends.example as Ada')
      const proof = proofFromPage(body)
      expect(acceptedIdentity(proof, publicKey, 1_700_000_000, 'https://login.example', 'https://friends.example')).toBe(
        deriveIdentity('apple', 'sub-9', 'friends.example', derivationKey),
      )
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('accepts the same cookie after the session file is loaded again', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const derivationKey = new TextEncoder().encode('0123456789abcdef0123456789abcdef')
    const sessions = await tempSessions()
    const options = {
      port: 0,
      issuer: 'https://login.example',
      keyId: 'k1',
      privateKey: secretKey,
      publicKey,
      derivationKey,
      now: () => 1_700_000_000,
      testLogin: true as const,
      providers: {},
      sessionsFile: sessions.file,
    }
    const first = await startLogin(options)
    let cookie = ''
    try {
      const res = await fetch(new URL('/test-login', first.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ provider: 'google', subject: 'sub-9', label: 'Ada' }),
      })
      expect(res.status).toBe(204)
      cookie = cookieValue(setCookie(res, 'valar_session'))
    } finally {
      await first.close()
    }
    const second = await startLogin(options)
    try {
      const connect = new URL('/connect', second.url)
      connect.searchParams.set('audience', 'https://friends.example')
      connect.searchParams.set('return', 'https://friends.example/room')
      const done = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${cookie}` } })
      expect(done.status).toBe(200)
      const body = await done.text()
      expect(body).toContain('Connecting to https://friends.example as Ada')
      const refreshed = setCookie(done, 'valar_session')
      expect(refreshed).toContain('HttpOnly')
      expect(refreshed).toContain('Secure')
      expect(refreshed).toContain('SameSite=Lax')
      expect(refreshed).toContain('Max-Age=34560000')
      expect(refreshed).not.toMatch(/Expires=/i)
      expect(cookieValue(refreshed)).toBe(cookie)
      const proof = proofFromPage(body)
      expect(acceptedIdentity(proof, publicKey, 1_700_000_000, 'https://login.example', 'https://friends.example')).toBe(
        deriveIdentity('google', 'sub-9', 'friends.example', derivationKey),
      )
      const loggedOut = await fetch(new URL('/logout', second.url), {
        method: 'POST',
        headers: { cookie: `valar_session=${cookie}` },
      })
      expect(setCookie(loggedOut, 'valar_session')).toContain('Max-Age=0')
    } finally {
      await second.close()
    }
    const third = await startLogin(options)
    try {
      const connect = new URL('/connect', third.url)
      connect.searchParams.set('audience', 'https://friends.example')
      connect.searchParams.set('return', 'https://friends.example/room')
      const again = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${cookie}` } })
      expect(again.status).toBe(200)
      expect(await again.text()).not.toContain('#signet-proof=')
    } finally {
      await third.close()
      await sessions.remove()
    }
  })

  it('rejects a session file that is not an object of sessions', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const sessions = await tempSessions()
    await writeFile(sessions.file, '[]', 'utf8')
    await expect(
      startLogin({
        port: 0,
        issuer: 'https://login.example',
        keyId: 'k1',
        privateKey: secretKey,
        publicKey,
        derivationKey: new TextEncoder().encode('0123456789abcdef0123456789abcdef'),
        sessionsFile: sessions.file,
      }),
    ).rejects.toThrow(/SIGNET_SESSIONS/)
    await sessions.remove()
  })

  it('shows a test sign-in instead of a blank page when no provider is configured', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const derivationKey = new TextEncoder().encode('0123456789abcdef0123456789abcdef')
    const sessions = await tempSessions()
    const issuer = 'http://192.0.2.10:8787'
    const audience = 'http://192.0.2.10:8080'
    const returnUrl = 'http://192.0.2.10:8080/'
    const server = await startLogin({
      port: 0,
      issuer,
      keyId: 'k1',
      privateKey: secretKey,
      publicKey,
      derivationKey,
      now: () => 1_700_000_000,
      testLogin: true,
      providers: {},
      sessionsFile: sessions.file,
    })
    try {
      const connect = new URL('/connect', server.url)
      connect.searchParams.set('audience', audience)
      connect.searchParams.set('return', returnUrl)
      const page = await fetch(connect)
      expect(page.status).toBe(200)
      expect(page.headers.get('content-type')).toContain('text/html')
      const html = await page.text()
      expect(html).not.toContain('<nav></nav>')
      expect(html).toContain('<button type="submit">Sign in</button>')
      expect(html).toContain('/test-login?')
      expect(html).not.toContain('/auth/google')

      const action = html.match(/action="([^"]+)"/)?.[1]?.replace(/&amp;/g, '&') ?? ''
      expect(action.startsWith('/test-login?')).toBe(true)
      const posted = await fetch(new URL(action, server.url), {
        method: 'POST',
        redirect: 'manual',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: '',
      })
      expect(posted.status).toBe(200)
      const body = await posted.text()
      expect(body).toContain('Connecting to http://192.0.2.10:8080 as Local')
      const line = setCookie(posted, 'valar_session')
      expect(line).toContain('HttpOnly')
      expect(line).toContain('SameSite=Lax')
      expect(cookieFlags(line)).not.toContain('Secure')
      const proof = proofFromPage(body)
      expect(readProofAudience(proof)).toBe(audience)
      expect(acceptedIdentity(proof, publicKey, 1_700_000_000, issuer, audience)).toBe(
        deriveIdentity('google', 'local', '192.0.2.10', derivationKey),
      )

      const again = await fetch(connect, {
        redirect: 'manual',
        headers: { cookie: `valar_session=${cookieValue(line)}` },
      })
      expect(again.status).toBe(200)
      const againBody = await again.text()
      expect(againBody).toContain('#signet-proof=')
      const refreshed = setCookie(again, 'valar_session')
      expect(refreshed).toContain('HttpOnly')
      expect(refreshed).toContain('SameSite=Lax')
      expect(cookieFlags(refreshed)).not.toContain('Secure')
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('keeps the session cookie Secure for a loopback http issuer', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const sessions = await tempSessions()
    const server = await startLogin({
      port: 0,
      issuer: 'http://127.0.0.1:8787',
      keyId: 'k1',
      privateKey: secretKey,
      publicKey,
      derivationKey: new TextEncoder().encode('0123456789abcdef0123456789abcdef'),
      now: () => 1_700_000_000,
      testLogin: true,
      providers: {},
      sessionsFile: sessions.file,
    })
    try {
      const res = await fetch(new URL('/test-login', server.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ provider: 'google', subject: 'local', label: 'Local' }),
      })
      expect(res.status).toBe(204)
      const line = setCookie(res, 'valar_session')
      expect(line).toContain('HttpOnly')
      expect(line).toContain('Secure')
      expect(line).toContain('SameSite=Lax')
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('requires SIGNET_SESSIONS', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const previous = process.env.SIGNET_SESSIONS
    delete process.env.SIGNET_SESSIONS
    try {
      await expect(
        startLogin({
          port: 0,
          issuer: 'https://login.example',
          keyId: 'k1',
          privateKey: secretKey,
          publicKey,
          derivationKey: new TextEncoder().encode('0123456789abcdef0123456789abcdef'),
        }),
      ).rejects.toThrow(/SIGNET_SESSIONS is required/)
    } finally {
      if (previous === undefined) delete process.env.SIGNET_SESSIONS
      else process.env.SIGNET_SESSIONS = previous
    }
  })

  it('does not accept a session path from VALAR_LOGIN_SESSIONS', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const previousSignet = process.env.SIGNET_SESSIONS
    const previousOld = process.env.VALAR_LOGIN_SESSIONS
    delete process.env.SIGNET_SESSIONS
    process.env.VALAR_LOGIN_SESSIONS = 'C:\\ignored\\sessions.json'
    try {
      await expect(
        startLogin({
          port: 0,
          issuer: 'https://login.example',
          keyId: 'k1',
          privateKey: secretKey,
          publicKey,
          derivationKey: new TextEncoder().encode('0123456789abcdef0123456789abcdef'),
        }),
      ).rejects.toThrow(/SIGNET_SESSIONS is required/)
    } finally {
      if (previousSignet === undefined) delete process.env.SIGNET_SESSIONS
      else process.env.SIGNET_SESSIONS = previousSignet
      if (previousOld === undefined) delete process.env.VALAR_LOGIN_SESSIONS
      else process.env.VALAR_LOGIN_SESSIONS = previousOld
    }
  })
})

describe('decideAgentProof', () => {
  it('signs the derived agent id and refuses a swapped audience', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const agent = await generateKeyPair()
    const derivationKey = new TextEncoder().encode('test-key')
    const now = 1_700_000_000
    const audience = 'http://127.0.0.1:8080'
    const signed = signAgentRequest(audience, agent.secretKey, now - 30)
    const keys = {
      now,
      issuer: 'https://login.example',
      keyId: 'k1',
      privateKey: secretKey,
      derivationKey,
    }
    const ok = decideAgentProof({
      ...keys,
      audience,
      publicKey: signed.publicKey,
      issuedAt: now - 30,
      signature: signed.signature,
    })
    expect(ok.type).toBe('proof')
    if (ok.type !== 'proof') return
    expect(acceptedIdentity(ok.proof, publicKey, now, 'https://login.example', audience)).toBe(
      deriveIdentity('agent', agentSubject(agent.publicKey), '127.0.0.1', derivationKey),
    )
    expect(readProofAudience(ok.proof)).toBe(audience)
    expect(readProofExpiry(ok.proof)).toBe(now + 15 * 60)
    expect(
      decideAgentProof({
        ...keys,
        audience: 'http://127.0.0.1:3000',
        publicKey: signed.publicKey,
        issuedAt: now - 30,
        signature: signed.signature,
      }).type,
    ).toBe('reject')
    const stale = signAgentRequest(audience, agent.secretKey, now - 61)
    expect(
      decideAgentProof({
        ...keys,
        audience,
        publicKey: stale.publicKey,
        issuedAt: now - 61,
        signature: stale.signature,
      }).type,
    ).toBe('reject')
    const edge = signAgentRequest(audience, agent.secretKey, now - 60)
    expect(
      decideAgentProof({ ...keys, audience, publicKey: edge.publicKey, issuedAt: now - 60, signature: edge.signature })
        .type,
    ).toBe('proof')
    const pathed = signAgentRequest('http://127.0.0.1:8080/session', agent.secretKey, now)
    expect(
      decideAgentProof({
        ...keys,
        audience: 'http://127.0.0.1:8080/session',
        publicKey: pathed.publicKey,
        issuedAt: now,
        signature: pathed.signature,
      }).type,
    ).toBe('reject')
  })

  it('does not create a session file', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const agent = await generateKeyPair()
    const sessions = await tempSessions()
    const now = 1_700_000_000
    const server = await startLogin({
      port: 0,
      issuer: 'https://login.example',
      keyId: 'k1',
      privateKey: secretKey,
      publicKey,
      derivationKey: new TextEncoder().encode('test-key'),
      now: () => now,
      testLogin: false,
      sessionsFile: sessions.file,
    })
    try {
      const audience = 'http://127.0.0.1:8080'
      const signed = signAgentRequest(audience, agent.secretKey, now)
      const body = JSON.stringify({
        audience,
        publicKey: Buffer.from(signed.publicKey).toString('base64url'),
        issuedAt: now,
        signature: Buffer.from(signed.signature).toString('base64url'),
      })
      const res = await fetch(new URL('/agent-proof', server.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body,
      })
      expect(res.status).toBe(200)
      const parsed = (await res.json()) as { proof: string }
      expect(parsed.proof).not.toContain('=')
      const proof = Buffer.from(parsed.proof, 'base64url')
      expect(acceptedIdentity(proof, publicKey, now, 'https://login.example', audience)).toBe(
        deriveIdentity('agent', agentSubject(agent.publicKey), '127.0.0.1', new TextEncoder().encode('test-key')),
      )
      const gone = await fetch(new URL('/agent-proof', server.url))
      expect(gone.status).toBe(405)
      await expect(readFile(sessions.file, 'utf8')).rejects.toThrow()
    } finally {
      await server.close()
      await sessions.remove()
    }
  })
})

async function tempSessions(): Promise<{ file: string; remove(): Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), 'valar-login-'))
  return {
    file: join(dir, 'sessions.json'),
    async remove() {
      await rm(dir, { recursive: true, force: true })
    },
  }
}

function authUrl(origin: string, audience: string, returnUrl: string, site?: string): URL {
  const url = new URL('/auth/google', origin)
  url.searchParams.set('audience', audience)
  url.searchParams.set('return', returnUrl)
  if (site !== undefined) url.searchParams.set('site', site)
  return url
}

function setCookie(res: Response, name: string): string {
  const line = res.headers.getSetCookie().find((item) => item.startsWith(`${name}=`))
  expect(line, name).toBeTruthy()
  return line ?? ''
}

function cookieValue(line: string): string {
  return line.slice(line.indexOf('=') + 1).split(';')[0] ?? ''
}

function cookieFlags(line: string): string {
  const semi = line.indexOf(';')
  return semi < 0 ? '' : line.slice(semi + 1)
}

function proofFromPage(html: string): Uint8Array {
  const marker = '#signet-proof='
  const at = html.indexOf(marker)
  expect(at).toBeGreaterThan(-1)
  const token = html.slice(at + marker.length).match(/^[A-Za-z0-9_-]+/)?.[0] ?? ''
  expect(token).not.toContain('=')
  return Buffer.from(token, 'base64url')
}
