import { verify } from '@noble/ed25519'
import { badProof, decodePayload } from './codec.js'
import './ed25519.js'

export function verifyProof(
  proof: Uint8Array,
  expected: {
    issuer: string
    audience: string
    keys: readonly { id: string; publicKey: Uint8Array }[]
    nowSeconds: number
  },
): string {
  const { claims, end } = decodePayload(proof)
  if (proof.length !== end + 64) badProof()
  if (!/^[0-9a-fA-F]{64}$/.test(claims.identity)) badProof()
  if (!(expected.nowSeconds <= claims.expiresAt + 60 && expected.nowSeconds + 60 >= claims.issuedAt)) badProof()
  const signature = proof.subarray(end)
  const payload = proof.subarray(0, end)
  let accepted = false
  for (const key of expected.keys) {
    let ok = false
    try {
      ok = verify(signature, payload, key.publicKey)
    } catch {
      ok = false
    }
    if (!ok) continue
    if (key.id !== claims.keyId) badProof()
    accepted = true
    break
  }
  if (!accepted) badProof()
  if (claims.issuer !== expected.issuer || claims.audience !== expected.audience) badProof()
  return claims.identity
}
