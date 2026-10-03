import { agentRequestOk, signProof } from '@agenticage/proof'
import { agentSubject, deriveIdentity } from './identity.js'
import type { ProviderName } from './identity.js'

export type LoginSession = { provider: ProviderName; subject: string; label: string }

export type ConnectDecision =
  | { type: 'providers' }
  | { type: 'reject' }
  | { type: 'redirect'; location: string }

const PROOF_SECONDS = 15 * 60

export function destinationName(audience: string, site?: string): string {
  if (site !== undefined && site.length > 0) return site
  return new URL(audience).hostname
}

export function connectingText(audience: string, label: string, site?: string): string {
  return `Signed in as ${label}. Taking you back to ${destinationName(audience, site)}.`
}

export function decideConnect(input: {
  session: LoginSession | null
  audience: string
  returnUrl: string
  now: number
  issuer: string
  keyId: string
  privateKey: Uint8Array
  derivationKey: Uint8Array
}): ConnectDecision {
  let returnUrl: URL
  try {
    returnUrl = new URL(input.returnUrl)
  } catch {
    return { type: 'reject' }
  }
  // The proof's fragment is a credential. Only the audience origin may receive it.
  if (returnUrl.protocol !== 'http:' && returnUrl.protocol !== 'https:') return { type: 'reject' }
  if (returnUrl.origin !== input.audience) return { type: 'reject' }
  if (input.session === null) return { type: 'providers' }

  let host: string
  try {
    host = new URL(input.audience).hostname
  } catch {
    return { type: 'reject' }
  }

  let identity: string
  try {
    identity = deriveIdentity(input.session.provider, input.session.subject, host, input.derivationKey)
  } catch (error) {
    if (error instanceof Error && (error.message === 'bad_host' || error.message === 'empty_subject')) {
      return { type: 'reject' }
    }
    throw error
  }

  const proof = signProof(
    {
      keyId: input.keyId,
      issuer: input.issuer,
      identity,
      audience: input.audience,
      issuedAt: input.now,
      expiresAt: input.now + PROOF_SECONDS,
    },
    input.privateKey,
  )
  // Node's base64url encoding has no '=' padding.
  const token = Buffer.from(proof).toString('base64url')
  returnUrl.hash = `signet-proof=${token}`
  if (/[\r\n]/.test(returnUrl.href)) return { type: 'reject' }
  return { type: 'redirect', location: returnUrl.href }
}

export function decideAgentProof(input: {
  audience: string
  publicKey: Uint8Array
  issuedAt: number
  signature: Uint8Array
  now: number
  issuer: string
  keyId: string
  privateKey: Uint8Array
  derivationKey: Uint8Array
}): { type: 'reject' } | { type: 'proof'; proof: Uint8Array } {
  if (!agentRequestOk(input.audience, input.publicKey, input.issuedAt, input.signature, input.now)) {
    return { type: 'reject' }
  }
  let url: URL
  try {
    url = new URL(input.audience)
  } catch {
    return { type: 'reject' }
  }
  if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.origin !== input.audience) {
    return { type: 'reject' }
  }
  let identity: string
  try {
    identity = deriveIdentity('agent', agentSubject(input.publicKey), url.hostname, input.derivationKey)
  } catch (error) {
    if (error instanceof Error && (error.message === 'bad_host' || error.message === 'empty_subject')) {
      return { type: 'reject' }
    }
    throw error
  }
  const proof = signProof(
    {
      keyId: input.keyId,
      issuer: input.issuer,
      identity,
      audience: input.audience,
      issuedAt: input.now,
      expiresAt: input.now + PROOF_SECONDS,
    },
    input.privateKey,
  )
  return { type: 'proof', proof }
}
