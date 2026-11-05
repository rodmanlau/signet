# Agent login authorization — type sketch

Status: implementation contract for the design at `2026-11-05-agent-login-authorization.md`.

## Domain

```ts
// packages/server/src/grants.ts (new)

export type AgentGrant = {
  ownerProvider: ProviderName // google | apple | facebook
  ownerSubject: string
  publicKey: Uint8Array // 32 bytes
  label: string // 1..200, no CR/LF/NUL
  createdAt: number // unix seconds
}

// Wire form in agent-grants.json: publicKey as unpadded base64url
export type AgentGrantRecord = {
  ownerProvider: ProviderName
  ownerSubject: string
  publicKey: string
  label: string
  createdAt: number
}

// Map key: hex(publicKey) — one public key, one owner
export type GrantStore = Map<string, AgentGrant>

export type AgentTicket = {
  id: string // random base64url, 16+ bytes entropy
  publicKey: Uint8Array
  label: string
  loopback?: string // optional http://127.0.0.1:<port> or http://localhost:<port> origin
  exp: number // now + 600
}
```

## Decisions in `decideAgentProof`

```ts
export function decideAgentProof(input: {
  // existing fields...
  granted: boolean // required; forgotten caller must not default to true
}): { type: 'reject' } | { type: 'unauthorized' } | { type: 'proof'; proof: Uint8Array }
```

Order: signature/audience checks → if !granted return unauthorized → derive + sign.

## HTTP

| Method | Path | Auth | Result |
| --- | --- | --- | --- |
| POST | `/agent-proof` | signed body | 200 proof / 403 `{unauthorized, skill}` / 400 rejected |
| POST | `/agents/ticket` | same signed body as agent-proof + `label` + optional `loopback` | 200 `{ approveUrl, ticket }` |
| GET | `/agents/approve?ticket=` | session optional | Allow page, or providers that return here |
| POST | `/agents/approve?ticket=` | session required | write grant, redirect to loopback or success |
| GET | `/agents` | session required | list + revoke forms |
| POST | `/agents/revoke` | session required | delete grant for that key owned by session |
| GET | `/agents/skill` | none | markdown skill text agents follow |

Grants file path: sibling of `SIGNET_SESSIONS` named `agent-grants.json`. Corrupt file → empty grants + stderr warning, process stays up.

## OAuth return

Extend pending login with optional `agentTicket?: string`. When set, callback lands on `/agents/approve?ticket=` instead of minting a site proof.

## Client

On `/agent-proof` → 403: POST `/agents/ticket`, print approve URL, listen on loopback if used, else poll `/agent-proof`.
