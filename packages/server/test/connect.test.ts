// @noble/ed25519 exports keygenAsync, not generateKeyPair. Same { secretKey, publicKey } shape.
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { keygenAsync as generateKeyPair } from '@noble/ed25519'
import { describe, expect, it } from 'vitest'
import { readProofAudience, readProofExpiry, signAgentRequest, verifyProof } from '@agenticage/proof'
import { agentSubject, deriveIdentity } from '../src/identity.js'
import { connectingText, decideAgentProof, decideConnect, destinationName } from '../src/connect.js'
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
    expect(destinationName('https://friends.example')).toBe('friends.example')
    expect(destinationName('https://friends.example', '')).toBe('friends.example')
    expect(destinationName('https://friends.example', 'Friends')).toBe('Friends')
    expect(destinationName('http://192.0.2.10:8080')).toBe('192.0.2.10')
    expect(connectingText('https://friends.example', 'ada@gmail.com')).toBe(
      'Signed in as ada@gmail.com. Taking you back to friends.example.',
    )
    expect(connectingText('https://friends.example', 'ada@gmail.com', 'Friends')).toBe(
      'Signed in as ada@gmail.com. Taking you back to Friends.',
    )
    expect(connectingText('https://friends.example', 'ada@gmail.com', '')).toBe(
      'Signed in as ada@gmail.com. Taking you back to friends.example.',
    )
    expect(connectingText('http://192.0.2.10:8080', 'Ada')).toBe(
      'Signed in as Ada. Taking you back to 192.0.2.10.',
    )
    expect(
      decideConnect({ ...keys, session: null, audience: 'https://friends.example', returnUrl: 'https://friends.example/room' })
        .type,
    ).toBe('providers')
  })
})

describe('login origin', () => {
  it('serves only the three official marks', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const sessions = await tempSessions()
    const server = await startLogin({
      port: 0,
      issuer: 'https://login.example',
      keyId: 'k1',
      privateKey: secretKey,
      publicKey,
      derivationKey: new TextEncoder().encode('0123456789abcdef0123456789abcdef'),
      now: () => 1_700_000_000,
      testLogin: false,
      providers: {},
      sessionsFile: sessions.file,
    })
    try {
      for (const name of ['google', 'apple', 'facebook']) {
        const mark = await fetch(new URL(`/marks/${name}.svg`, server.url))
        expect(mark.status).toBe(200)
        expect(mark.headers.get('content-type')).toContain('image/svg+xml')
        expect(await mark.text()).toContain('<svg')
      }
      const missing = await fetch(new URL('/marks/other.svg', server.url))
      expect(missing.status).toBe(404)
      expect(await missing.text()).toBe('not found')
      const escaped = await fetch(new URL('/marks/../package.json', server.url))
      expect(escaped.status).toBe(404)
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('tells the person how to sign in', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const derivationKey = new TextEncoder().encode('0123456789abcdef0123456789abcdef')
    const sessions = await tempSessions()
    const server = await startLogin({
      port: 0,
      issuer: 'https://login.example',
      keyId: 'k1',
      privateKey: secretKey,
      publicKey,
      derivationKey,
      now: () => 1_700_000_000,
      testLogin: false,
      sessionsFile: sessions.file,
      providers: {
        google: { clientId: 'google-client', exchange: async () => ({ subject: 's', label: 'Ada' }) },
        apple: { clientId: 'apple-client', exchange: async () => ({ subject: 's', label: 'Ada' }) },
        facebook: { clientId: 'facebook-client', exchange: async () => ({ subject: 's', label: 'Ada' }) },
      },
    })
    try {
      const connect = new URL('/connect', server.url)
      connect.searchParams.set('audience', 'https://friends.example')
      connect.searchParams.set('return', 'https://friends.example/room')
      const page = await fetch(connect)
      expect(page.status).toBe(200)
      const html = await page.text()
      expect(html).toContain('<title>Sign in</title>')
      expect(html).toContain('<h1>Sign in</h1>')
      expect(html).toContain(
        'To continue to friends.example, choose an account. You sign in on that site, then come back here.',
      )
      expect(html).not.toContain('no-provider')
      const google = html.indexOf('Continue with Google')
      const apple = html.indexOf('Continue with Apple')
      const facebook = html.indexOf('Continue with Facebook')
      expect(google).toBeGreaterThan(-1)
      expect(apple).toBeGreaterThan(google)
      expect(facebook).toBeGreaterThan(apple)
      expect(html).toContain('src="/marks/google.svg"')
      expect(html).toContain('src="/marks/apple.svg"')
      expect(html).toContain('src="/marks/facebook.svg"')
      expect(html).not.toContain('https://developers.google.com')
      expect(html).not.toContain('https://appleid.apple.com')
      expect(html).not.toContain('https://www.facebook.com')
      expect(html).toContain('/auth/google?')
      expect(html).toContain('audience=https%3A%2F%2Ffriends.example')
      expect(html).toContain('return=https%3A%2F%2Ffriends.example%2Froom')
      expect(html).toContain('width="20" height="20"')
      expect(html).toContain('alt=""')
      expect(html).toContain('width:320px')
      expect(html).toContain('height:40px')

      const named = new URL('/connect', server.url)
      named.searchParams.set('audience', 'https://friends.example')
      named.searchParams.set('return', 'https://friends.example/room')
      named.searchParams.set('site', '<Friends & co>')
      const namedHtml = await (await fetch(named)).text()
      expect(namedHtml).toContain('To continue to &lt;Friends &amp; co&gt;, choose an account.')
      expect(namedHtml).not.toContain('To continue to <Friends')
      expect(namedHtml).not.toContain('friends.example, choose an account')

      const blankSite = new URL('/connect', server.url)
      blankSite.searchParams.set('audience', 'http://192.0.2.10:8080')
      blankSite.searchParams.set('return', 'http://192.0.2.10:8080/')
      blankSite.searchParams.set('site', '')
      const blankHtml = await (await fetch(blankSite)).text()
      expect(blankHtml).toContain('To continue to 192.0.2.10, choose an account.')
      expect(blankHtml).not.toContain('192.0.2.10:8080, choose an account')
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('warns no-provider when no account button can be shown', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const derivationKey = new TextEncoder().encode('0123456789abcdef0123456789abcdef')
    const sessions = await tempSessions()
    const open = async (
      providers: Record<string, { clientId: string; exchange: () => Promise<{ subject: string; label: string }> }>,
      testLogin: boolean,
    ) => {
      const server = await startLogin({
        port: 0,
        issuer: 'https://login.example',
        keyId: 'k1',
        privateKey: secretKey,
        publicKey,
        derivationKey,
        now: () => 1_700_000_000,
        testLogin,
        providers,
        sessionsFile: sessions.file,
      })
      const connect = new URL('/connect', server.url)
      connect.searchParams.set('audience', 'https://friends.example')
      connect.searchParams.set('return', 'https://friends.example/room')
      const html = await (await fetch(connect)).text()
      await server.close()
      return html
    }
    try {
      const exchange = async () => ({ subject: 's', label: 'Ada' })
      const empty = await open({}, false)
      expect(empty).toContain('<h1>Sign in</h1>')
      expect(empty).toContain('Sign-in is not set up.')
      expect(empty).toContain('no-provider')
      expect(empty).not.toContain('/auth/google')
      expect(empty).not.toContain('/auth/apple')
      expect(empty).not.toContain('/auth/facebook')

      const spaces = await open({ google: { clientId: '   ', exchange } }, false)
      expect(spaces).toContain('no-provider')
      expect(spaces).not.toContain('Continue with Google')

      const googleOnly = await open({ google: { clientId: 'google-client', exchange } }, false)
      expect(googleOnly).toContain('Continue with Google')
      expect(googleOnly).not.toContain('Continue with Apple')
      expect(googleOnly).not.toContain('Continue with Facebook')
      expect(googleOnly).not.toContain('no-provider')

      const testOnly = await open({}, true)
      expect(testOnly).toContain('<button type="submit">Sign in</button>')
      expect(testOnly).toContain('/test-login?')
      expect(testOnly).not.toContain('no-provider')
    } finally {
      await sessions.remove()
    }
  })

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
      expect(backBody).toContain('Signed in as ada@gmail.com. Taking you back to Friends.')
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
      expect(doneBody).toContain('Signed in as ada@gmail.com. Taking you back to Friends.')
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
      expect(body).toContain('Signed in as Ada. Taking you back to friends.example.')
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
      expect(body).toContain('Signed in as Ada. Taking you back to friends.example.')
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
      expect(body).toContain('Signed in as Local. Taking you back to 192.0.2.10.')
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

  it('signs the browser out from the sign-out page', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const sessions = await tempSessions()
    const server = await startLogin({
      port: 0,
      issuer: 'https://login.example',
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
      const minted = await fetch(new URL('/test-login', server.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ provider: 'google', subject: 'ada', label: 'A&B <ada>' }),
      })
      const session = cookieValue(setCookie(minted, 'valar_session'))
      const signOut = new URL('/sign-out', server.url)
      signOut.searchParams.set('audience', 'https://friends.example')
      signOut.searchParams.set('return', 'https://friends.example/room?x=1#keep')
      const page = await fetch(signOut, { headers: { cookie: `valar_session=${session}` } })
      expect(page.status).toBe(200)
      expect(page.headers.getSetCookie().some((line) => line.startsWith('valar_session='))).toBe(false)
      const html = await page.text()
      expect(html).toContain('<title>Sign out</title>')
      expect(html).toContain('<h1>Sign out</h1>')
      expect(html).toContain('You are signed in as A&amp;B &lt;ada&gt;.')
      expect(html).toContain('<button type="submit">Sign out</button>')
      expect(html).toContain('method="post"')
      expect(html).toContain('action="/sign-out?')
      expect(html).toContain('audience=https%3A%2F%2Ffriends.example')
      expect(html).not.toContain('Continue with Google')
      expect(html).not.toContain('Stay signed in')
      expect(html).not.toContain('signet-identity=cancelled')

      const connect = new URL('/connect', server.url)
      connect.searchParams.set('audience', 'https://friends.example')
      connect.searchParams.set('return', 'https://friends.example/room')
      const still = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${session}` } })
      expect(still.status).toBe(200)
      expect(await still.text()).toContain('Signed in as A&amp;B &lt;ada&gt;.')

      const evil = new URL('/sign-out', server.url)
      evil.searchParams.set('audience', 'https://friends.example')
      evil.searchParams.set('return', 'https://evil.example/room')
      const rejected = await fetch(evil, {
        method: 'POST',
        redirect: 'manual',
        headers: { cookie: `valar_session=${session}` },
      })
      expect(rejected.status).toBe(400)
      expect(rejected.headers.get('location')).toBeNull()
      const kept = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${session}` } })
      expect(await kept.text()).toContain('Signed in as A&amp;B &lt;ada&gt;.')

      const other = await fetch(signOut, { method: 'PUT', redirect: 'manual' })
      expect(other.status).toBe(405)
      expect(other.headers.get('allow')).toBe('GET, POST')

      const posted = await fetch(signOut, {
        method: 'POST',
        redirect: 'manual',
        headers: { cookie: `valar_session=${session}` },
      })
      expect(posted.status).toBe(303)
      expect(await posted.text()).toBe('signed-out')
      const back = new URL(posted.headers.get('location') ?? '')
      expect(back.origin).toBe('https://friends.example')
      expect(back.pathname).toBe('/room')
      expect(back.search).toBe('?x=1')
      expect(back.hash).toBe('#signet-identity=signed-out')
      const cleared = setCookie(posted, 'valar_session')
      expect(cleared).toContain('Max-Age=0')
      expect(setCookie(posted, 'valar_oauth')).toContain('Max-Age=0')

      const after = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${session}` } })
      expect(await after.text()).toContain('<h1>Sign in</h1>')

      const gone = await fetch(signOut, { redirect: 'manual' })
      expect(gone.status).toBe(303)
      expect(new URL(gone.headers.get('location') ?? '').hash).toBe('#signet-identity=signed-out')
      const gonePost = await fetch(signOut, { method: 'POST', redirect: 'manual' })
      expect(gonePost.status).toBe(303)
      expect(new URL(gonePost.headers.get('location') ?? '').hash).toBe('#signet-identity=signed-out')
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('offers the configured accounts on the switch page', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const exchange = async () => ({ subject: 'ada', label: 'Ada' })
    const sessionsOn = await tempSessions()
    const on = await startLogin({
      port: 0,
      issuer: 'https://login.example',
      keyId: 'k1',
      privateKey: secretKey,
      publicKey,
      derivationKey: new TextEncoder().encode('0123456789abcdef0123456789abcdef'),
      now: () => 1_700_000_000,
      testLogin: true,
      sessionsFile: sessionsOn.file,
      providers: {
        google: { clientId: 'google-client', authorizeUrl: 'https://provider.test/auth', exchange },
        apple: { clientId: 'apple-client', authorizeUrl: 'https://apple.test/auth', exchange },
        facebook: { clientId: 'facebook-client', authorizeUrl: 'https://facebook.test/auth', exchange },
      },
    })
    try {
      const minted = await fetch(new URL('/test-login', on.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ provider: 'google', subject: 'ada', label: 'A&B <ada>' }),
      })
      const session = cookieValue(setCookie(minted, 'valar_session'))
      const cookie = { cookie: `valar_session=${session}` }
      const switchUrl = new URL('/switch', on.url)
      switchUrl.searchParams.set('audience', 'https://friends.example')
      switchUrl.searchParams.set('return', 'https://friends.example/room')
      const page = await fetch(switchUrl, { headers: cookie })
      expect(page.status).toBe(200)
      expect(page.headers.getSetCookie().some((line) => line.startsWith('valar_session='))).toBe(false)
      const html = await page.text()
      expect(html).toContain('<title>Switch account</title>')
      expect(html).toContain('<h1>Switch account</h1>')
      expect(html).toContain('You are signed in as A&amp;B &lt;ada&gt;.')
      expect(html).toContain('Continue with Google')
      expect(html).toContain('Continue with Apple')
      expect(html).toContain('Continue with Facebook')
      expect(html).not.toContain('>Sign out<')
      expect(html).not.toContain('no-provider')
      // href text escapes & as &amp;. Decode before reading the query.
      const googleHref = html.match(/href="([^"]*\/auth\/google[^"]*)"/)?.[1]?.replaceAll('&amp;', '&') ?? ''
      const appleHref = html.match(/href="([^"]*\/auth\/apple[^"]*)"/)?.[1]?.replaceAll('&amp;', '&') ?? ''
      const facebookHref = html.match(/href="([^"]*\/auth\/facebook[^"]*)"/)?.[1]?.replaceAll('&amp;', '&') ?? ''
      expect(new URL(googleHref, on.url).searchParams.get('prompt')).toBe('select_account')
      expect(new URL(appleHref, on.url).searchParams.get('prompt')).toBeNull()
      expect(new URL(facebookHref, on.url).searchParams.get('prompt')).toBeNull()
      expect(html.indexOf('Continue with Google')).toBeLessThan(html.indexOf('Continue with Apple'))
      expect(html.indexOf('Continue with Apple')).toBeLessThan(html.indexOf('Continue with Facebook'))

      const bare = await fetch(switchUrl)
      const bareHtml = await bare.text()
      expect(bareHtml).toContain('<title>Sign in</title>')
      expect(bareHtml).toContain('choose an account')
      expect(bareHtml).not.toContain('You are signed in as')
      expect(bareHtml).not.toContain('prompt=select_account')

      const posted = await fetch(switchUrl, { method: 'POST' })
      expect(posted.status).toBe(405)
      expect(posted.headers.get('allow')).toBe('GET')

      const google = new URL('/auth/google', on.url)
      google.searchParams.set('audience', 'https://friends.example')
      google.searchParams.set('return', 'https://friends.example/room')
      google.searchParams.set('prompt', 'select_account')
      const began = await fetch(google, { redirect: 'manual' })
      expect(new URL(began.headers.get('location') ?? '').searchParams.get('prompt')).toBe('select_account')

      const plain = new URL('/auth/google', on.url)
      plain.searchParams.set('audience', 'https://friends.example')
      plain.searchParams.set('return', 'https://friends.example/room')
      const plainBegan = await fetch(plain, { redirect: 'manual' })
      expect(new URL(plainBegan.headers.get('location') ?? '').searchParams.get('prompt')).toBeNull()

      const loginPrompt = new URL(google)
      loginPrompt.searchParams.set('prompt', 'login')
      const ignored = await fetch(loginPrompt, { redirect: 'manual' })
      expect(new URL(ignored.headers.get('location') ?? '').searchParams.get('prompt')).toBeNull()

      const apple = new URL('/auth/apple', on.url)
      apple.searchParams.set('audience', 'https://friends.example')
      apple.searchParams.set('return', 'https://friends.example/room')
      apple.searchParams.set('prompt', 'select_account')
      const appleBegan = await fetch(apple, { redirect: 'manual' })
      expect(new URL(appleBegan.headers.get('location') ?? '').searchParams.get('prompt')).toBeNull()
    } finally {
      await on.close()
      await sessionsOn.remove()
    }

    const quietSessions = await tempSessions()
    const quietId = 'quiet-session-id1'
    await writeFile(
      quietSessions.file,
      JSON.stringify({ [quietId]: { provider: 'google', subject: 'ada', label: 'Ada' } }),
    )
    const quiet = await startLogin({
      port: 0,
      issuer: 'https://login.example',
      keyId: 'k1',
      privateKey: secretKey,
      publicKey,
      derivationKey: new TextEncoder().encode('0123456789abcdef0123456789abcdef'),
      now: () => 1_700_000_000,
      testLogin: false,
      providers: {},
      sessionsFile: quietSessions.file,
    })
    const formSessions = await tempSessions()
    const form = await startLogin({
      port: 0,
      issuer: 'https://login.example',
      keyId: 'k1',
      privateKey: secretKey,
      publicKey,
      derivationKey: new TextEncoder().encode('0123456789abcdef0123456789abcdef'),
      now: () => 1_700_000_000,
      testLogin: true,
      providers: {},
      sessionsFile: formSessions.file,
    })
    try {
      const quietPage = new URL('/switch', quiet.url)
      quietPage.searchParams.set('audience', 'https://friends.example')
      quietPage.searchParams.set('return', 'https://friends.example/room')
      const warned = await fetch(quietPage, { headers: { cookie: `valar_session=${quietId}` } })
      const warnedHtml = await warned.text()
      expect(warnedHtml).toContain('You are signed in as Ada.')
      expect(warnedHtml).toContain('Sign-in is not set up.')
      expect(warnedHtml).toContain('no-provider')
      expect(warnedHtml).not.toContain('/auth/google')

      const minted = await fetch(new URL('/test-login', form.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ provider: 'google', subject: 'ada', label: 'Ada' }),
      })
      const formCookie = cookieValue(setCookie(minted, 'valar_session'))
      const formPage = new URL('/switch', form.url)
      formPage.searchParams.set('audience', 'https://friends.example')
      formPage.searchParams.set('return', 'https://friends.example/room')
      const formed = await fetch(formPage, { headers: { cookie: `valar_session=${formCookie}` } })
      const formedHtml = await formed.text()
      expect(formedHtml).toContain('You are signed in as Ada.')
      expect(formedHtml).toContain('<button type="submit">Sign in</button>')
      expect(formedHtml).not.toContain('no-provider')
    } finally {
      await quiet.close()
      await form.close()
      await quietSessions.remove()
      await formSessions.remove()
    }
  })

  it('replaces the browser account when a new sign-in finishes', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const derivationKey = new TextEncoder().encode('0123456789abcdef0123456789abcdef')
    let subject = 'ada'
    let label = 'Ada'
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
      sessionsFile: sessions.file,
      providers: {
        google: {
          clientId: 'google-client',
          authorizeUrl: 'https://provider.test/auth',
          exchange: async (code) => {
            if (code === 'bad') throw new Error('provider down')
            return { subject, label }
          },
        },
      },
    })
    const connect = new URL('/connect', server.url)
    connect.searchParams.set('audience', 'https://friends.example')
    connect.searchParams.set('return', 'https://friends.example/room')
    const finish = async (code: string, session?: string) => {
      const start = new URL('/auth/google', server.url)
      start.searchParams.set('audience', 'https://friends.example')
      start.searchParams.set('return', 'https://friends.example/room')
      const began = await fetch(start, { redirect: 'manual' })
      const state = new URL(began.headers.get('location') ?? '').searchParams.get('state') ?? ''
      const nonce = cookieValue(setCookie(began, 'valar_oauth'))
      const callback = new URL('/auth/google/callback', server.url)
      callback.searchParams.set('code', code)
      callback.searchParams.set('state', state)
      const headers: Record<string, string> = { cookie: `valar_oauth=${nonce}` }
      if (session !== undefined) headers.cookie = `valar_oauth=${nonce}; valar_session=${session}`
      return fetch(callback, { redirect: 'manual', headers })
    }
    try {
      const first = await finish('ok')
      expect(first.status).toBe(200)
      const firstId = cookieValue(setCookie(first, 'valar_session'))

      subject = 'bea'
      label = 'Bea'
      const failed = await finish('bad', firstId)
      expect(failed.status).toBe(303)
      expect(new URL(failed.headers.get('location') ?? '').hash).toBe('#signet-identity=failed')
      const still = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${firstId}` } })
      expect(await still.text()).toContain('Signed in as Ada.')

      const second = await finish('ok', firstId)
      expect(second.status).toBe(200)
      expect(await second.text()).toContain('Signed in as Bea. Taking you back to friends.example.')
      const secondId = cookieValue(setCookie(second, 'valar_session'))
      expect(secondId).not.toBe(firstId)
      const stored = JSON.parse(await readFile(sessions.file, 'utf8')) as Record<string, { label: string }>
      expect(Object.keys(stored)).toEqual([secondId])
      expect(stored[secondId]?.label).toBe('Bea')
      const old = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${firstId}` } })
      expect(await old.text()).toContain('<h1>Sign in</h1>')
      const newer = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${secondId}` } })
      expect(await newer.text()).toContain('Signed in as Bea.')

      subject = 'bea'
      label = 'Bea'
      const same = await finish('ok', secondId)
      const sameId = cookieValue(setCookie(same, 'valar_session'))
      expect(sameId).not.toBe(secondId)
      const afterSame = JSON.parse(await readFile(sessions.file, 'utf8')) as Record<string, { subject: string }>
      expect(Object.keys(afterSame)).toEqual([sameId])
      expect(afterSame[sameId]?.subject).toBe('bea')
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('drops the previous account when Apple posts the callback', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const derivationKey = new TextEncoder().encode('0123456789abcdef0123456789abcdef')
    let subject = 'ada'
    let label = 'Ada'
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
      sessionsFile: sessions.file,
      providers: {
        apple: {
          clientId: 'apple-client',
          authorizeUrl: 'https://apple.test/auth',
          exchange: async () => ({ subject, label }),
        },
      },
    })
    const connect = new URL('/connect', server.url)
    connect.searchParams.set('audience', 'https://friends.example')
    connect.searchParams.set('return', 'https://friends.example/room')
    const begin = async (session: string) => {
      const start = new URL('/auth/apple', server.url)
      start.searchParams.set('audience', 'https://friends.example')
      start.searchParams.set('return', 'https://friends.example/room')
      const began = await fetch(start, { redirect: 'manual', headers: { cookie: `valar_session=${session}` } })
      const state = new URL(began.headers.get('location') ?? '').searchParams.get('state') ?? ''
      return { began, state, nonce: cookieValue(setCookie(began, 'valar_oauth')) }
    }
    const applePost = (state: string, fields: Record<string, string>, cookie: string) => {
      return fetch(new URL('/auth/apple/callback', server.url), {
        method: 'POST',
        redirect: 'manual',
        headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
        body: new URLSearchParams(fields).toString(),
      })
    }
    try {
      const minted = await fetch(new URL('/test-login', server.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ provider: 'google', subject: 'ada', label: 'Ada' }),
      })
      const firstId = cookieValue(setCookie(minted, 'valar_session'))
      const started = await begin(firstId)
      expect(started.began.status).toBe(302)
      const prior = setCookie(started.began, 'valar_prior')
      expect(cookieValue(prior)).toBe(firstId)
      expect(cookieFlags(prior)).toContain('HttpOnly')
      expect(cookieFlags(prior)).toContain('Secure')
      expect(cookieFlags(prior)).toContain('SameSite=None')
      expect(prior).toContain('Max-Age=600')
      expect(started.state).toBeTruthy()
      expect(started.state).not.toContain(firstId)

      const failed = await applePost(
        started.state,
        { error: 'access_denied', state: started.state },
        `valar_oauth=${started.nonce}; valar_prior=${firstId}`,
      )
      expect(failed.status).toBe(303)
      expect(new URL(failed.headers.get('location') ?? '').hash).toBe('#signet-identity=failed')
      expect(setCookie(failed, 'valar_prior')).toContain('Max-Age=0')
      const kept = JSON.parse(await readFile(sessions.file, 'utf8')) as Record<string, { label: string }>
      expect(kept[firstId]?.label).toBe('Ada')
      const still = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${firstId}` } })
      expect(await still.text()).toContain('Signed in as Ada.')

      subject = 'bea'
      label = 'Bea'
      const again = await begin(firstId)
      const posted = await applePost(
        again.state,
        { code: 'ok', state: again.state },
        `valar_oauth=${again.nonce}; valar_prior=${firstId}`,
      )
      expect(posted.status).toBe(200)
      const secondId = cookieValue(setCookie(posted, 'valar_session'))
      expect(secondId).not.toBe(firstId)
      expect(setCookie(posted, 'valar_prior')).toContain('Max-Age=0')
      const replaced = JSON.parse(await readFile(sessions.file, 'utf8')) as Record<string, { label: string }>
      expect(replaced[firstId]).toBeUndefined()
      expect(Object.keys(replaced)).toEqual([secondId])
      const old = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${firstId}` } })
      expect(await old.text()).toContain('<h1>Sign in</h1>')

      const extra = await fetch(new URL('/test-login', server.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ provider: 'google', subject: 'cy', label: 'Cy' }),
      })
      const thirdId = cookieValue(setCookie(extra, 'valar_session'))
      expect(thirdId).not.toBe(secondId)
      const both = JSON.parse(await readFile(sessions.file, 'utf8')) as Record<string, unknown>
      expect(Object.keys(both).sort()).toEqual([secondId, thirdId].sort())
      subject = 'dee'
      label = 'Dee'
      const third = await begin(secondId)
      const dropped = await applePost(
        third.state,
        { code: 'ok', state: third.state },
        `valar_oauth=${third.nonce}; valar_session=${secondId}; valar_prior=${thirdId}`,
      )
      expect(dropped.status).toBe(200)
      const fourthId = cookieValue(setCookie(dropped, 'valar_session'))
      const left = JSON.parse(await readFile(sessions.file, 'utf8')) as Record<string, unknown>
      expect(Object.keys(left)).toEqual([fourthId])
    } finally {
      await server.close()
      await sessions.remove()
    }
  })

  it('rejects a present but invalid test-login query without dropping the account', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const sessions = await tempSessions()
    const server = await startLogin({
      port: 0,
      issuer: 'https://login.example',
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
      const minted = await fetch(new URL('/test-login', server.url), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ provider: 'google', subject: 'ada', label: 'Ada' }),
      })
      const firstId = cookieValue(setCookie(minted, 'valar_session'))
      const bad = new URL('/test-login', server.url)
      bad.searchParams.set('audience', 'https://friends.example')
      bad.searchParams.set('return', 'https://friends.example/room')
      bad.searchParams.set('site', 'Friends\nroom')
      const rejected = await fetch(bad, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          cookie: `valar_session=${firstId}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ provider: 'google', subject: 'bea', label: 'Bea' }),
      })
      expect(rejected.status).toBe(400)
      expect(await rejected.text()).toBe('rejected')
      expect(rejected.headers.get('location')).toBeNull()
      const kept = JSON.parse(await readFile(sessions.file, 'utf8')) as Record<string, { label: string }>
      expect(Object.keys(kept)).toEqual([firstId])
      expect(kept[firstId]?.label).toBe('Ada')

      const again = await fetch(new URL('/test-login', server.url), {
        method: 'POST',
        redirect: 'manual',
        headers: {
          cookie: `valar_session=${firstId}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ provider: 'google', subject: 'bea', label: 'Bea' }),
      })
      expect(again.status).toBe(204)
      const nextId = cookieValue(setCookie(again, 'valar_session'))
      expect(nextId).not.toBe(firstId)
      const replaced = JSON.parse(await readFile(sessions.file, 'utf8')) as Record<string, { label: string }>
      expect(Object.keys(replaced)).toEqual([nextId])
    } finally {
      await server.close()
      await sessions.remove()
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
