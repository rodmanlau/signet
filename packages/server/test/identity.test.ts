import { keygenAsync as generateKeyPair } from '@noble/ed25519'
import { describe, expect, it } from 'vitest'
import { agentSubject, deriveIdentity } from '../src/identity.js'

describe('deriveIdentity', () => {
  const key = new TextEncoder().encode('test-key')

  it('uses the registrable domain and ignores scheme, port, and www', () => {
    const id = deriveIdentity('google', 'sub-1', 'www.example.com', key)
    expect(id).toHaveLength(64)
    expect(deriveIdentity('google', 'sub-1', 'play.example.com', key)).toBe(id)
    expect(deriveIdentity('google', 'sub-1', 'foo.bar.co.uk', key)).toBe(deriveIdentity('google', 'sub-1', 'bar.co.uk', key))
    expect(deriveIdentity('google', 'sub-1', 'alice.github.io', key)).not.toBe(
      deriveIdentity('google', 'sub-1', 'bob.github.io', key),
    )
    expect(deriveIdentity('google', 'sub-1', '127.0.0.1', key)).toBe(deriveIdentity('google', 'sub-1', '127.0.0.1', key))
    expect(deriveIdentity('google', 'sub-1', 'localhost', key)).not.toBe(deriveIdentity('google', 'sub-1', '127.0.0.1', key))
    expect(deriveIdentity('google', 'sub-1', 'example.com', key)).not.toBe(
      deriveIdentity('google', 'sub-1', 'example.com', new TextEncoder().encode('other-key')),
    )
    expect(() => deriveIdentity('google', 'sub-1', 'b', key)).toThrow(/bad_host/)
  })

  it('does not alias when a subject contains a NUL', () => {
    expect(deriveIdentity('google', 'a\0example.com', 'other.com', key)).not.toBe(
      deriveIdentity('google', 'a', 'example.com', key),
    )
  })

  it('names an agent from the public key', async () => {
    const { publicKey } = await generateKeyPair()
    const subject = agentSubject(publicKey)
    expect(subject).toHaveLength(64)
    expect(subject).toBe(subject.toLowerCase())
    const id = deriveIdentity('agent', subject, 'www.example.com', key)
    expect(deriveIdentity('agent', subject, 'play.example.com', key)).toBe(id)
    expect(deriveIdentity('agent', subject, 'http://play.example.com:8443', key)).toBe(id)
    expect(deriveIdentity('agent', subject, 'example.co.uk', key)).not.toBe(id)
    expect(deriveIdentity('google', subject, 'www.example.com', key)).not.toBe(id)
    expect(() => agentSubject(Uint8Array.of(1))).toThrow(/bad_key/)
  })
})
