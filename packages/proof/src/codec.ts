const utf8 = new TextEncoder()

export type ProofClaims = {
  keyId: string
  issuer: string
  identity: string
  audience: string
  issuedAt: number
  expiresAt: number
}

export function badProof(): never {
  throw new Error('bad_proof')
}

export function requireU32(value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) badProof()
}

export class Writer {
  #parts: Uint8Array[] = []
  #length = 0

  u8(value: number): void {
    const bytes = new Uint8Array(1)
    bytes[0] = value
    this.#parts.push(bytes)
    this.#length += 1
  }

  u16(value: number): void {
    const bytes = new Uint8Array(2)
    new DataView(bytes.buffer).setUint16(0, value, true)
    this.#parts.push(bytes)
    this.#length += 2
  }

  u32(value: number): void {
    const bytes = new Uint8Array(4)
    new DataView(bytes.buffer).setUint32(0, value, true)
    this.#parts.push(bytes)
    this.#length += 4
  }

  bytes(value: Uint8Array): void {
    this.#parts.push(value)
    this.#length += value.length
  }

  counted(text: string, width: 1 | 2): void {
    const bytes = utf8.encode(text)
    const max = width === 1 ? 255 : 65535
    if (bytes.length > max) badProof()
    if (width === 1) this.u8(bytes.length)
    else this.u16(bytes.length)
    this.bytes(bytes)
  }

  finish(): Uint8Array {
    const out = new Uint8Array(this.#length)
    let offset = 0
    for (const part of this.#parts) {
      out.set(part, offset)
      offset += part.length
    }
    return out
  }
}

class Reader {
  #bytes: Uint8Array
  #view: DataView
  #off = 0

  constructor(bytes: Uint8Array) {
    this.#bytes = bytes
    this.#view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  }

  #need(n: number): void {
    if (this.#off + n > this.#bytes.length) badProof()
  }

  u8(): number {
    this.#need(1)
    const value = this.#view.getUint8(this.#off)
    this.#off += 1
    return value
  }

  u16(): number {
    this.#need(2)
    const value = this.#view.getUint16(this.#off, true)
    this.#off += 2
    return value
  }

  u32(): number {
    this.#need(4)
    const value = this.#view.getUint32(this.#off, true)
    this.#off += 4
    return value
  }

  bytes(n: number): Uint8Array {
    this.#need(n)
    const out = this.#bytes.subarray(this.#off, this.#off + n)
    this.#off += n
    return out
  }

  counted(width: 1 | 2): string {
    const n = width === 1 ? this.u8() : this.u16()
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(this.bytes(n))
    } catch {
      badProof()
    }
  }

  offset(): number {
    return this.#off
  }
}

export function encodePayload(claims: ProofClaims): Uint8Array {
  requireU32(claims.issuedAt)
  requireU32(claims.expiresAt)
  const writer = new Writer()
  writer.u8(1)
  writer.counted(claims.keyId, 1)
  writer.counted(claims.issuer, 2)
  writer.counted(claims.identity, 1)
  writer.counted(claims.audience, 2)
  writer.u32(claims.issuedAt)
  writer.u32(claims.expiresAt)
  return writer.finish()
}

export function decodePayload(proof: Uint8Array): { claims: ProofClaims; end: number } {
  const reader = new Reader(proof)
  if (reader.u8() !== 1) badProof()
  const claims = {
    keyId: reader.counted(1),
    issuer: reader.counted(2),
    identity: reader.counted(1),
    audience: reader.counted(2),
    issuedAt: reader.u32(),
    expiresAt: reader.u32(),
  }
  return { claims, end: reader.offset() }
}
