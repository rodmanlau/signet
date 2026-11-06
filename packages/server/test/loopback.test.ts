import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { keygenAsync as generateKeyPair } from '@noble/ed25519'
import { describe, expect, it } from 'vitest'
import { readProofAudience, readProofExpiry, verifyProof } from '@agenticage/proof'
import { deriveIdentity } from '../src/identity.js'
import {
  LOOPBACK_AUDIENCE,
  LOOPBACK_PORT,
  decideLoopbackProof,
  loopbackFromEnv,
  startLoopbackIssuer,
} from '../src/loopback.js'
import { startLogin } from '../src/main.js'

const NOW = 1_700_000_000
const RETURN_URL = 'http://127.0.0.1:8080/room?x=1#keep'

function keysOf(secret: Uint8Array, derivation: Uint8Array, issuer = 'http://127.0.0.1:8790') {
  return {
    now: NOW,
    issuer,
    keyId: 'k1',
    privateKey: secret,
    derivationKey: derivation,
  }
}

function proofFromLocation(location: string): Uint8Array {
  const encoded = new URL(location).hash.slice('#signet-proof='.length)
  return Buffer.from(encoded, 'base64url')
}

function proofFromPage(html: string): Uint8Array {
  const match = html.match(/location\.replace\((.*)\)\},1000\)/)
  if (!match?.[1]) throw new Error('no redirect')
  const location = JSON.parse(match[1]) as string
  return proofFromLocation(location)
}

describe('decideLoopbackProof', () => {
  it('signs only http://127.0.0.1:8080 for one stable subject', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const derivation = new TextEncoder().encode('loopback-derivation-key')
    const input = keysOf(secretKey, derivation)
    const first = decideLoopbackProof({ ...input, audience: LOOPBACK_AUDIENCE, returnUrl: RETURN_URL })
    expect(first.type).toBe('redirect')
    if (first.type !== 'redirect') return
    expect(first.location.startsWith('http://127.0.0.1:8080/room?x=1#signet-proof=')).toBe(true)
    expect(first.location).not.toContain('keep')
    const proof = proofFromLocation(first.location)
    expect(readProofAudience(proof)).toBe(LOOPBACK_AUDIENCE)
    expect(readProofExpiry(proof)).toBe(NOW + 15 * 60)
    const identity = verifyProof(proof, {
      issuer: input.issuer,
      audience: LOOPBACK_AUDIENCE,
      keys: [{ id: 'k1', publicKey }],
      nowSeconds: NOW,
    })
    expect(identity).toBe(deriveIdentity('google', 'local', '127.0.0.1', derivation))
    const again = decideLoopbackProof({
      ...input,
      now: NOW + 30,
      audience: LOOPBACK_AUDIENCE,
      returnUrl: 'http://127.0.0.1:8080/other',
    })
    expect(again.type).toBe('redirect')
    if (again.type !== 'redirect') return
    const second = proofFromLocation(again.location)
    expect(
      verifyProof(second, {
        issuer: input.issuer,
        audience: LOOPBACK_AUDIENCE,
        keys: [{ id: 'k1', publicKey }],
        nowSeconds: NOW + 30,
      }),
    ).toBe(identity)

    const otherKey = new TextEncoder().encode('other-loopback-derivation')
    const other = decideLoopbackProof({
      ...input,
      derivationKey: otherKey,
      audience: LOOPBACK_AUDIENCE,
      returnUrl: 'http://127.0.0.1:8080/',
    })
    expect(other.type).toBe('redirect')
    if (other.type !== 'redirect') return
    expect(
      verifyProof(proofFromLocation(other.location), {
        issuer: input.issuer,
        audience: LOOPBACK_AUDIENCE,
        keys: [{ id: 'k1', publicKey }],
        nowSeconds: NOW,
      }),
    ).not.toBe(identity)

    expect(() =>
      verifyProof(proof, {
        issuer: 'https://signet.fly.dev',
        audience: LOOPBACK_AUDIENCE,
        keys: [{ id: 'k1', publicKey }],
        nowSeconds: NOW,
      }),
    ).toThrow(/bad_proof/)
    expect(() =>
      verifyProof(proof, {
        issuer: input.issuer,
        audience: 'https://valar.example',
        keys: [{ id: 'k1', publicKey }],
        nowSeconds: NOW,
      }),
    ).toThrow(/bad_proof/)
    expect(() =>
      verifyProof(proof, {
        issuer: input.issuer,
        audience: 'http://127.0.0.1:3000',
        keys: [{ id: 'k1', publicKey }],
        nowSeconds: NOW,
      }),
    ).toThrow(/bad_proof/)
  })

  it('rejects every audience and issuer other than the loopback pair', async () => {
    const { secretKey } = await generateKeyPair()
    const input = keysOf(secretKey, new TextEncoder().encode('loopback-derivation-key'))
    const audiences = [
      'https://valar.example',
      'https://signet.fly.dev',
      'http://localhost:8080',
      'http://[::1]:8080',
      'http://127.0.0.2:8080',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:8080/',
      'http://127.0.0.1:8080/room',
      'http://user@127.0.0.1:8080',
      'https://127.0.0.1:8080',
    ]
    for (const audience of audiences) {
      expect(decideLoopbackProof({ ...input, audience, returnUrl: 'http://127.0.0.1:8080/room' }).type).toBe('reject')
    }
    const returns = [
      'https://valar.example/room',
      'http://127.0.0.1:3000/room',
      'http://localhost:8080/room',
      'http://[::1]:8080/room',
      'http://user:pass@127.0.0.1:8080/room',
      'javascript:alert(1)',
      'not a url',
    ]
    for (const returnUrl of returns) {
      expect(decideLoopbackProof({ ...input, audience: LOOPBACK_AUDIENCE, returnUrl }).type).toBe('reject')
    }
    const issuers = [
      'https://signet.fly.dev',
      'http://127.0.0.1:8080',
      'http://127.0.0.1',
      'http://localhost:8790',
      'http://0.0.0.0:8790',
      'https://127.0.0.1:8790',
    ]
    for (const issuer of issuers) {
      expect(
        decideLoopbackProof({ ...input, issuer, audience: LOOPBACK_AUDIENCE, returnUrl: 'http://127.0.0.1:8080/room' })
          .type,
      ).toBe('reject')
    }
  })
})

describe('loopback issuer', () => {
  it('returns a proof a local client can verify, and nothing for any other route', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const derivation = new TextEncoder().encode('loopback-http-derivation')
    const server = await startLoopbackIssuer({
      port: 0,
      privateKey: secretKey,
      publicKey,
      derivationKey: derivation,
      now: () => NOW,
    })
    try {
      expect(server.url.startsWith('http://127.0.0.1:')).toBe(true)
      expect(server.url).not.toBe(LOOPBACK_AUDIENCE)
      const connect = new URL('/connect', server.url)
      connect.searchParams.set('audience', LOOPBACK_AUDIENCE)
      connect.searchParams.set('return', 'http://127.0.0.1:8080/room?x=1')
      connect.searchParams.set('site', 'Friends & Co')
      const page = await fetch(connect)
      expect(page.status).toBe(200)
      expect(page.headers.get('set-cookie')).toBeNull()
      const html = await page.text()
      expect(html).toContain('Signed in as Local. Taking you back to Friends &amp; Co.')
      expect(html).not.toContain('Friends & Co')
      const proof = proofFromPage(html)
      expect(
        verifyProof(proof, {
          issuer: server.url,
          audience: LOOPBACK_AUDIENCE,
          keys: [{ id: 'k1', publicKey }],
          nowSeconds: NOW,
        }),
      ).toBe(deriveIdentity('google', 'local', '127.0.0.1', derivation))

      const keys = await fetch(new URL('/.well-known/signet-keys', server.url))
      expect(keys.status).toBe(200)
      const published = (await keys.json()) as { keys: { id: string; publicKey: string }[] }
      expect(published.keys).toEqual([{ id: 'k1', publicKey: Buffer.from(publicKey).toString('base64') }])

      const wrong = new URL('/connect', server.url)
      wrong.searchParams.set('audience', 'https://valar.example')
      wrong.searchParams.set('return', 'https://valar.example/room')
      const rejected = await fetch(wrong)
      expect(rejected.status).toBe(400)
      expect(await rejected.text()).toBe('rejected')

      for (const path of ['/test-login', '/agent-proof', '/agents', '/agents/approve', '/auth/google']) {
        const res = await fetch(new URL(path, server.url), { method: 'POST' })
        expect(res.status).toBe(404)
        expect(await res.text()).toBe('not found')
      }
      const posted = await fetch(connect, { method: 'POST' })
      expect(posted.status).toBe(405)
    } finally {
      await server.close()
    }
  })

  it('refuses the audience port, a public issuer, and a production environment', async () => {
    const { secretKey } = await generateKeyPair()
    const derivation = new TextEncoder().encode('loopback-env-derivation-key!!')
    await expect(
      startLoopbackIssuer({
        port: 8080,
        privateKey: secretKey,
        derivationKey: derivation,
      }),
    ).rejects.toThrow('loopback issuer cannot listen on the audience port')
    await expect(
      startLoopbackIssuer({
        port: 0,
        issuer: 'https://signet.fly.dev',
        privateKey: secretKey,
        derivationKey: derivation,
      }),
    ).rejects.toThrow('loopback issuer origin must be http://127.0.0.1:<port>')

    const env = {
      SIGNET_LOOPBACK_PRIVATE_KEY: Buffer.from(secretKey).toString('base64'),
      SIGNET_LOOPBACK_DERIVATION_KEY: Buffer.from(derivation).toString('base64'),
      SIGNET_PORT: '8787',
      SIGNET_KEY_ID: 'other',
    }
    expect(loopbackFromEnv(env)).toMatchObject({
      port: LOOPBACK_PORT,
      issuer: `http://127.0.0.1:${LOOPBACK_PORT}`,
      keyId: 'k1',
    })
    expect(() =>
      loopbackFromEnv({
        ...env,
        SIGNET_HOST: '0.0.0.0',
        SIGNET_ISSUER: 'https://signet.fly.dev',
        SIGNET_PRIVATE_KEY: Buffer.from(secretKey).toString('base64'),
        SIGNET_DERIVATION_KEY: Buffer.from(derivation).toString('base64'),
        SIGNET_TEST: '1',
      }),
    ).toThrow('refusing to start the loopback issuer while SIGNET_PRIVATE_KEY is set')
    expect(() => loopbackFromEnv({ ...env, SIGNET_HOST: '0.0.0.0' })).toThrow('loopback issuer listens on 127.0.0.1')
    expect(() => loopbackFromEnv({ ...env, SIGNET_ISSUER: 'https://signet.fly.dev' })).toThrow(
      'loopback issuer origin must be http://127.0.0.1:<port>',
    )
    expect(() => loopbackFromEnv({ ...env, SIGNET_LOOPBACK_PORT: '8080' })).toThrow('SIGNET_LOOPBACK_PORT is invalid')
  })

  it('leaves the production connect route unsigned for this audience', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const dir = await mkdtemp(join(tmpdir(), 'signet-loopback-prod-'))
    const server = await startLogin({
      port: 0,
      issuer: 'https://signet.fly.dev',
      keyId: 'k1',
      privateKey: secretKey,
      publicKey,
      derivationKey: new TextEncoder().encode('production-derivation-key'),
      now: () => NOW,
      testLogin: false,
      sessionsFile: join(dir, 'sessions.json'),
    })
    try {
      const connect = new URL('/connect', server.url)
      connect.searchParams.set('audience', LOOPBACK_AUDIENCE)
      connect.searchParams.set('return', 'http://127.0.0.1:8080/room')
      const page = await fetch(connect)
      expect(page.status).toBe(200)
      const html = await page.text()
      expect(html).not.toContain('signet-proof')
      expect(html).toContain('no-provider')
    } finally {
      await server.close()
      await rm(dir, { recursive: true, force: true })
    }
  })
})
