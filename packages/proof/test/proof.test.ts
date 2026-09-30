import { readdirSync, readFileSync } from 'node:fs'
import { keygenAsync as generateKeyPair } from '@noble/ed25519'
import { describe, expect, it } from 'vitest'
import {
  agentRequestOk,
  readProofAudience,
  readProofExpiry,
  signAgentRequest,
  signProof,
  verifyProof,
} from '../src/index.js'
import type { ProofClaims } from '../src/index.js'

const IDENTITY = 'ab'.repeat(32)

function claims(over: Partial<ProofClaims> = {}): ProofClaims {
  return {
    keyId: 'k1',
    issuer: 'https://login.example',
    identity: IDENTITY,
    audience: 'https://www.example.com',
    issuedAt: 1_000,
    expiresAt: 2_000,
    ...over,
  }
}

async function minted(over: Partial<ProofClaims> = {}) {
  const { secretKey, publicKey } = await generateKeyPair()
  const body = claims(over)
  return { secretKey, publicKey, body, proof: signProof(body, secretKey) }
}

function accept(
  proof: Uint8Array,
  publicKey: Uint8Array,
  body: ProofClaims,
  nowSeconds: number,
  keys?: readonly { id: string; publicKey: Uint8Array }[],
): string {
  return verifyProof(proof, {
    issuer: body.issuer,
    audience: body.audience,
    keys: keys ?? [{ id: body.keyId, publicKey }],
    nowSeconds,
  })
}

describe('verifyProof', () => {
  it('returns the identity when the signature, key id, issuer, audience, and time match', async () => {
    const { publicKey, body, proof } = await minted()
    expect(accept(proof, publicKey, body, 1_500)).toBe(IDENTITY)
    expect(accept(proof, publicKey, body, 2_060)).toBe(IDENTITY)
    expect(accept(proof, publicKey, body, 940)).toBe(IDENTITY)
  })

  it('throws when the audience or the issuer differs', async () => {
    const { publicKey, body, proof } = await minted()
    expect(() =>
      verifyProof(proof, {
        issuer: body.issuer,
        audience: 'https://world.example.com',
        keys: [{ id: 'k1', publicKey }],
        nowSeconds: 1_500,
      }),
    ).toThrow(/bad_proof/)
    expect(() =>
      verifyProof(proof, {
        issuer: 'https://login.example/',
        audience: body.audience,
        keys: [{ id: 'k1', publicKey }],
        nowSeconds: 1_500,
      }),
    ).toThrow(/bad_proof/)
    expect(() => accept(proof, publicKey, body, 2_061)).toThrow(/bad_proof/)
    expect(() => accept(proof, publicKey, body, 939)).toThrow(/bad_proof/)
  })

  it('stops the walk when the verifying key has the wrong id', async () => {
    const { publicKey, body, proof } = await minted()
    expect(() =>
      accept(proof, publicKey, body, 1_500, [
        { id: 'other', publicKey },
        { id: 'k1', publicKey },
      ]),
    ).toThrow(/bad_proof/)
  })

  it('skips a key that does not verify and accepts a later match', async () => {
    const { publicKey, body, proof } = await minted()
    const other = await generateKeyPair()
    expect(
      accept(proof, publicKey, body, 1_500, [
        { id: 'k1', publicKey: other.publicKey },
        { id: 'k1', publicKey },
      ]),
    ).toBe(IDENTITY)
  })

  it('does not accept a matching key id whose signature fails', async () => {
    const { body, proof } = await minted()
    const other = await generateKeyPair()
    expect(() =>
      verifyProof(proof, {
        issuer: body.issuer,
        audience: body.audience,
        keys: [{ id: 'k1', publicKey: other.publicKey }],
        nowSeconds: 1_500,
      }),
    ).toThrow(/bad_proof/)
  })

  it('throws when no keys are configured', async () => {
    const { body, proof } = await minted()
    expect(() =>
      verifyProof(proof, {
        issuer: body.issuer,
        audience: body.audience,
        keys: [],
        nowSeconds: 1_500,
      }),
    ).toThrow(/bad_proof/)
  })
})

describe('readers', () => {
  it('returns the audience and expiry when the signature is wrong', async () => {
    const { proof } = await minted()
    const tampered = new Uint8Array(proof)
    tampered[tampered.length - 1] ^= 0xff
    expect(readProofAudience(tampered)).toBe('https://www.example.com')
    expect(readProofExpiry(tampered)).toBe(2_000)
    const unsigned = proof.subarray(0, proof.length - 64)
    expect(readProofExpiry(unsigned)).toBe(2_000)
    const badVersion = new Uint8Array(proof)
    badVersion[0] = 2
    expect(() => readProofAudience(badVersion)).toThrow(/bad_proof/)
    expect(() => readProofAudience(proof.subarray(0, 3))).toThrow(/bad_proof/)
  })
})

describe('agent request', () => {
  it('signs a request and rejects a clock or audience outside the window', async () => {
    const { secretKey, publicKey } = await generateKeyPair()
    const signed = signAgentRequest('http://127.0.0.1:8080', secretKey, 1_000)
    expect(signed.publicKey).toEqual(publicKey)
    expect(agentRequestOk('http://127.0.0.1:8080', signed.publicKey, 1_000, signed.signature, 1_060)).toBe(true)
    expect(agentRequestOk('http://127.0.0.1:8080', signed.publicKey, 1_000, signed.signature, 1_061)).toBe(false)
    expect(agentRequestOk('http://127.0.0.1:3000', signed.publicKey, 1_000, signed.signature, 1_000)).toBe(false)
    const flipped = new Uint8Array(signed.signature)
    flipped[0] ^= 0xff
    expect(agentRequestOk('http://127.0.0.1:8080', signed.publicKey, 1_000, flipped, 1_000)).toBe(false)
    expect(() => signAgentRequest('http://127.0.0.1:8080', Uint8Array.of(1), 1_000)).toThrow(/bad_key/)
  })
})

describe('surface', () => {
  it('exports the proof API and does not reach the network or node', async () => {
    const proof = await import('../src/index.js')
    expect(Object.keys(proof).sort()).toEqual([
      'agentRequestOk',
      'readProofAudience',
      'readProofExpiry',
      'signAgentRequest',
      'signProof',
      'verifyProof',
    ])
    const index = readFileSync(new URL('../src/index.ts', import.meta.url), 'utf8')
    expect(index).toContain('export type { ProofClaims }')
    expect(index.split('\n').filter((line) => line.trim() !== '').every((line) => line.startsWith('export '))).toBe(true)
    const read = readFileSync(new URL('../src/read.ts', import.meta.url), 'utf8')
    expect(read).not.toMatch(/@noble/)
    const src = new URL('../src/', import.meta.url)
    for (const name of readdirSync(src)) {
      const text = readFileSync(new URL(name, src), 'utf8')
      expect(text).not.toMatch(/node:/)
      expect(text).not.toMatch(/\bfetch\s*\(/)
      expect(text).not.toMatch(/tldts|getDomain|well-known/)
    }
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      dependencies: Record<string, string>
      sideEffects: boolean
      scripts?: Record<string, string>
    }
    expect(pkg.dependencies).toEqual({
      '@noble/ed25519': '^3.2.0',
      '@noble/hashes': '^2.4.0',
    })
    expect(pkg.sideEffects).toBe(false)
    expect(pkg.scripts?.install).toBeUndefined()
    expect(pkg.scripts?.preinstall).toBeUndefined()
    expect(pkg.scripts?.postinstall).toBeUndefined()
  })
})
