import { sign } from '@noble/ed25519'
import { badProof, encodePayload } from './codec.js'
import type { ProofClaims } from './codec.js'
import './ed25519.js'

export function signProof(claims: ProofClaims, privateKey: Uint8Array): Uint8Array {
  const payload = encodePayload(claims)
  const signature = sign(payload, privateKey)
  if (signature.length !== 64) badProof()
  const proof = new Uint8Array(payload.length + 64)
  proof.set(payload, 0)
  proof.set(signature, payload.length)
  return proof
}
