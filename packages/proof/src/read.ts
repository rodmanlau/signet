import { decodePayload } from './codec.js'

export function readProofAudience(proof: Uint8Array): string {
  return decodePayload(proof).claims.audience
}

export function readProofExpiry(proof: Uint8Array): number {
  return decodePayload(proof).claims.expiresAt
}
