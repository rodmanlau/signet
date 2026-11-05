# Agent login authorization

Date: 2026-11-05

Status: design for review.

## Purpose

Re-enable agent login so a person's authorized agents can mint Signet proofs, while unknown agents are refused. Authorize and revoke must need little technical knowledge and few steps.

The first product is Cursor coding agents. Later products such as Grok Bot, Muse, Claude Duet, Hermes, OpenClaw, and OpenAI Dots reuse the same door.

Today any ed25519 key that signs correctly receives a 15-minute proof from `POST /agent-proof`. Signet stores nothing about that key. The change is to refuse unknown keys and let a signed-in person allow or revoke one.

## Background

### Agent path today

The agent signs a request with `signAgentRequest` and posts JSON to `/agent-proof`. `handleAgentProof` calls `decideAgentProof`. That function checks the signature and the audience origin, derives an identity with provider `agent` and the hex public key as the subject, then signs a proof. It never reads a session or an allowlist.

The signed message is version byte 1, the audience, the 32-byte public key, and `issuedAt`. There is no product name, user id, or nonce in those bytes.

### Human path today

A person signs in with Google, Apple, or Facebook. The stable person key is `provider` plus `subject`. The session cookie id changes on every successful sign-in and is the wrong key for a lasting grant.

`GET /connect` is not a consent screen for the audience. After one sign-in, any matching audience receives a proof. Sign-out ends one browser session. It does not end the person's identity.

### Storage today

The only durable server state is one JSON session file on one machine. On Fly that path is `/data/sessions.json` on one volume. The process loads the file into a map at startup. The map is the authority. A change rewrites the whole file.

`validSession` accepts only `google`, `apple`, and `facebook`. A session entry with provider `agent` fails startup. Extra fields on a valid session are dropped on the next write. Grants cannot live in `sessions.json`.

### Limits that every approach shares

Proofs last 15 minutes. Sites verify offline with `@agenticage/proof`. Signet is not called again. Revoking a grant stops the next mint. It cannot pull back a proof a site already holds. Human sign-out already works this way.

`valar_session` is `SameSite=Lax`. Allow and Revoke must be forms on a page Signet itself served. A cross-site `POST` does not send the cookie.

## Recommendation

Build a deep-link approval flow. The agent keeps its own identity. Put the grant check in `decideAgentProof` after a good signature. Store grants in a sibling JSON file on the same volume as sessions. Do not change the published proof bytes.

## Chosen approach

### User steps

1. In Cursor, the person asks to connect Signet.
2. A browser opens a Signet page. If they are not signed in, they use Continue with Google, Apple, or Facebook and return to this page.
3. The page says the app calls itself Cursor, shows a short fingerprint of the agent public key, and offers one Allow button.
4. After Allow, Cursor's next `POST /agent-proof` succeeds.
5. Revoke is a list at `GET /agents`. Each row shows the label, the time, the short fingerprint, and a Revoke button.
6. Browser sign-out does not revoke. The list belongs to the Google, Apple, or Facebook subject, so another browser of the same person still sees it.

### Storage

A second file beside the session file:

- Fly: `/data/agent-grants.json`
- Local setup: `.signet/agent-grants.json`

No new environment variable and no `fly.toml` change are required when the grants file is a sibling of `SIGNET_SESSIONS` on the same volume.

Each grant stores:

- `ownerProvider`
- `ownerSubject`
- the 32-byte agent public key
- `label`
- `createdAt`

One public key has one owner. The same owner approving again updates the label. A missing file means no grants. Use the same temp-file rewrite and mode `0600` as sessions. A corrupt grants file must not throw out of `startLogin`. Log it, refuse every agent proof, and keep human login up.

### Possession ticket

The approve URL carries a ticket id, not a bare public key. The agent first posts a ticket with the same signed body `/agent-proof` already uses. `agentRequestOk` must pass. Signet stores the ticket in memory for about 10 minutes, the same window as the OAuth pending login. The URL is `/agents/approve?ticket=...`.

Restarting the process drops open tickets. Grants stay on disk. The ticket proves the caller holds the key before the person clicks Allow. A raw `?publicKey=` link cannot prove possession. A signature in the query dies after 60 seconds, which is shorter than a first-time Google login.

### Gate

`decideAgentProof` gains a required granted check after the signature and the origin check, and before `signProof`. A valid signature with no grant returns `403` with body `unauthorized`. Bad crypto stays `400` with body `rejected`.

New pages are HTML strings in `packages/server/src/main.ts`, the same pattern as sign-in and sign-out. `GET` shows the form. `POST` writes the grant. Do not grant on `GET`.

The OAuth callback today always finishes in `decideConnect` and mints a proof for `return`. The approve page is not a site return. The sealed pending login needs a same-issuer path back to `/agents/approve?ticket=...`, and that path stays under `/agents`.

The published `signAgentRequest` bytes stay version 1. The proof codec stays version 1. The proof subject stays `deriveIdentity('agent', hex(publicKey), domain)`.

### Cursor, then other products

Do not branch on the string Cursor. The ticket request includes a label, length-capped like session labels (200 characters, no newlines). The page says the app supplied that name. The next product sends its own label on the same route. A label is not a credential.

### Reference client

On `403`, the reference client requests a ticket and prints the approve URL so the failure is an action, not a dead end.

### Deploy effect

On deploy, every key that works today starts getting `403` until that person allows it. That is the re-enable.

## Alternatives considered

### Pairing code

Same grant file, same `403` gate, same agent identity. The agent shows a short code. The person opens Signet, signs in if needed, types the code, and clicks Allow.

Pros: works when the agent cannot open a browser. The person does not paste a 32-byte key.

Cons: more steps than a click. A second door to build and test.

Build this only if the first Cursor client cannot open a URL. The ticket map can grow a short code then. Do not invent a second grant model.

### Operator allowlist of public keys

Someone pastes agent public keys into a Fly secret or a file, then deploys or restarts. Removing a key is the same operation.

Pros: small server diff. No OAuth work.

Cons: no per-person authorize or revoke. Fly secrets need a deploy to apply. A file edited on the volume is invisible until restart. There is no owner field. The key is allowed for every audience and every person.

Do not build this. It does not solve the problem.

### Vendor-attested agents, plus a user grant

Cursor holds a vendor ed25519 key and signs each agent public key. Signet pins Cursor's public key. The Allow page can say Cursor confirmed the key. The user still clicks Allow for their own account.

Pros: stops an app that only claims the name Cursor. User steps do not grow. Verifiers still do not change.

Cons: the first Cursor integration waits on a vendor key and a signature format this repository does not have. Vendor attestation with no user grant would let any Cursor agent mint again, which repeats today's open route inside one vendor.

Defer until a vendor key exists. Until then, keep saying the app supplied the name. Do not refuse unknown product labels.

### Approved agent uses the human's identity

Same Allow and Revoke. `decideAgentProof` would derive the owner's human identity instead of the agent identity. The codec does not change. Sites that only know the person would accept the agent with no site change.

Cons: a coding agent that holds the grant can mint the person's identity for every audience until revoke. Sites cannot tell an agent proof from a human proof. Browser sign-out does not stop the agent. That is a larger grant than the problem asks for.

Defer unless a real site accepts the human subject and rejects the agent subject. Do not prebuild a mode flag.

## Comparison

| | Deep link | Pairing code | Operator list | Vendor plus user grant | Act as the human |
| --- | --- | --- | --- | --- | --- |
| User action | Open the page, click Allow | Type a code, click Allow | Paste a key and redeploy | Same Allow click | Same Allow click |
| Revoke | That person, one button | That person, one button | Operator only | That person, one button | That person, but sites still see the person |
| Proof subject | Agent key | Agent key | Agent key | Agent key | The human |
| Published proof bytes | Unchanged | Unchanged | Unchanged | Unchanged | Unchanged codec, different identity |
| Extra work outside Signet | Open a URL | Show a code | None | Cursor must sign with a vendor key | Open a URL |
| When | Build now | Only if no browser | Do not build | When a vendor key exists | Only if a site must see the human |

## Deferred

- Pairing codes, until a product cannot open a browser.
- Vendor badges, until Cursor can sign agent keys.
- Act-as-human identity, until a real site needs it.
- Per-audience grants. Human login already mints for any matching audience after one sign-in.
- A proof version that names the human, the agent key, or the product. Current verifiers require version byte 1.
- An operator key list, including as a temporary bridge.
- Putting grants in `sessions.json`.
- An agent nonce cache. After the gate, a replay inside 60 seconds still needs the grant.

## Implementation map

| Piece | Path | Role |
| --- | --- | --- |
| Signed agent message | `packages/proof/src/agent.ts` | Leave the version 1 bytes. |
| Mint decision | `packages/server/src/connect.ts` | Add the grant check in `decideAgentProof` after the signature. |
| Identity | `packages/server/src/identity.ts` | Keep `deriveIdentity('agent', ...)`. |
| HTTP, cookies, HTML, files | `packages/server/src/main.ts` | New `/agents` pages, ticket issue, grant load and persist. |
| Session and grant tests | `packages/server/test/connect.test.ts` | Keep "does not create a session file" for `sessions.json`. Add `403` and the grant file. |
| Reference client | `packages/client/src/run.ts` | On `403`, request a ticket and print the URL. |
| Guides | `docs/develop.md`, `docs/admin.md` | Document the gate, the 15-minute revoke limit, and the grants file. |
| Fly | `fly.toml` | Volume `/data`. No edit required if the grants file is a sibling of sessions. |

## Gotchas

- Revoke and sign-out stop new proofs only. A site that already has the proof keeps accepting it until `expiresAt`, and `verifyProof` still allows 60 seconds past that.
- Do not key grants by session id. Key them by `provider` plus `subject`.
- Do not store grants in `sessions.json`.
- The product name is not in the signed request. Store the label at approval time. Do not authorize from it.
- Keep the agent identity in the proof for this gate. Do not switch to the human identity in a later deploy without an explicit product decision.
- Filter every list and every revoke by the signed-in owner. There is no operator account that should see all rows.
- The agents page cannot reuse `audience` and `return`. Those parameters exist to deliver a proof to a site.
- The reference client's key file is the agent. A new file is a new public key and needs a new Allow. The old grant stays until someone revokes it.
