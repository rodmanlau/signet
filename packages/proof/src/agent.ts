import { getPublicKey, sign, verify } from '@noble/ed25519'
import { badProof, requireU32, Writer } from './codec.js'
import './ed25519.js'

function agentRequestMessage(audience: string, publicKey: Uint8Array, issuedAt: number): Uint8Array {
  if (publicKey.length !== 32) badProof()
  requireU32(issuedAt)
  const writer = new Writer()
  writer.u8(1)
  writer.counted(audience, 2)
  writer.bytes(publicKey)
  writer.u32(issuedAt)
  return writer.finish()
}

export function signAgentRequest(
  audience: string,
  secretKey: Uint8Array,
  issuedAt: number,
): { publicKey: Uint8Array; signature: Uint8Array } {
  if (secretKey.length !== 32) throw new Error('bad_key')
  const publicKey = getPublicKey(secretKey)
  const signature = sign(agentRequestMessage(audience, publicKey, issuedAt), secretKey)
  return { publicKey, signature }
}

export function agentRequestOk(
  audience: string,
  publicKey: Uint8Array,
  issuedAt: number,
  signature: Uint8Array,
  nowSeconds: number,
): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false
  if (!Number.isInteger(issuedAt) || issuedAt < nowSeconds - 60 || issuedAt > nowSeconds + 60) return false
  try {
    return verify(signature, agentRequestMessage(audience, publicKey, issuedAt), publicKey)
  } catch {
    return false
  }
}
