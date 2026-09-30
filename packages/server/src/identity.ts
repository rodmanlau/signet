import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { getDomain } from 'tldts'

const utf8 = new TextEncoder()

function hex(bytes: Uint8Array): string {
  let out = ''
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0')
  return out
}

function joinNul(parts: Uint8Array[]): Uint8Array {
  let length = parts.length - 1
  for (const part of parts) length += part.length
  const out = new Uint8Array(length)
  let offset = 0
  for (let i = 0; i < parts.length; i++) {
    if (i > 0) out[offset++] = 0
    out.set(parts[i], offset)
    offset += parts[i].length
  }
  return out
}

function bareHost(input: string): string {
  let host = input
  if (host.includes('://')) {
    try {
      host = new URL(host).hostname
    } catch {
      throw new Error('bad_host')
    }
  }
  host = host.toLowerCase()
  if (host.startsWith('[')) {
    const end = host.indexOf(']')
    const rest = end < 0 ? '' : host.slice(end + 1)
    if (end < 0 || (rest !== '' && !/^:\d+$/.test(rest))) throw new Error('bad_host')
    host = host.slice(1, end)
  } else {
    const colon = host.lastIndexOf(':')
    if (colon > 0 && host.indexOf(':') === colon && /^\d+$/.test(host.slice(colon + 1))) {
      host = host.slice(0, colon)
    }
  }
  if (host.endsWith('.')) host = host.slice(0, -1)
  if (host === '') throw new Error('bad_host')
  return host
}

function isIpv4(host: string): boolean {
  const parts = host.split('.')
  if (parts.length !== 4) return false
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}

function isIpv6(host: string): boolean {
  if (!host.includes(':')) return false
  try {
    const hostname = new URL(`http://[${host}]`).hostname
    return hostname.startsWith('[') && hostname.endsWith(']')
  } catch {
    return false
  }
}

function registrableDomain(input: string): string {
  const host = bareHost(input)
  // github.io is a private suffix. tldts skips those unless asked.
  const domain = getDomain(host, { allowPrivateDomains: true })
  if (domain) return domain
  if (host === 'localhost' || isIpv4(host) || isIpv6(host)) return host
  throw new Error('bad_host')
}

export function deriveIdentity(provider: IdentityProvider, subject: string, host: string, key: Uint8Array): string {
  if (subject === '') throw new Error('empty_subject')
  const message = joinNul([utf8.encode(provider), utf8.encode(subject), utf8.encode(registrableDomain(host))])
  return hex(hmac(sha256, key, message))
}

export function agentSubject(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new Error('bad_key')
  return hex(publicKey)
}

export type ProviderName = 'google' | 'apple' | 'facebook'

export type IdentityProvider = ProviderName | 'agent'
