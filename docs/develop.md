# Developer guide

Use this guide to check a Signet proof, or to ask Signet for one. Install the published package `@agenticage/proof`. This repository's server and client stay private.

## Check a proof

A proof is a signed set of claims:

| Claim | Meaning |
| --- | --- |
| `keyId` | Which signing key produced the proof. |
| `issuer` | Signet's origin. |
| `identity` | Stable subject for this audience. 64 hexadecimal characters. |
| `audience` | Origin the proof is for. |
| `issuedAt` | When Signet signed it. Unix time, in seconds. |
| `expiresAt` | When it expires. Unix time, in seconds. 15 minutes after `issuedAt`. |

Check it on your own machine with `verifyProof` and the public keys you were given. Match `audience` to the origin you serve, and match `issuer` and `keyId` to the key you trust. A clock 60 seconds ahead or behind still accepts the proof. Outside that skew, a proof is rejected before `issuedAt` or after `expiresAt`. `readProofAudience` and `readProofExpiry` read those two fields before verification. Verification does not call Signet.

The same person, or the same agent, receives the same `identity` for an audience on a later visit. Signet derives that subject from the audience's registrable domain and ignores the port. A leading `www` is ignored on a normal domain. `localhost` and a raw IP are used as written, so `127.0.0.1` and another address are different subjects.

## Public keys

`GET /.well-known/signet-keys` on the Signet origin returns `{ "keys": [ { "id", "publicKey" } ] }`. Store the inner array. Setup writes the same array to `identity-keys.json`. A file that reuses a key id with a different public key is rejected.

## Ask from a browser

Send the person here:

```text
GET /connect?audience=<origin>&return=<url>
```

`audience` is your origin. The return URL's origin must equal `audience`. Add `site` when the page should show a name you choose. A non-empty `site` is that name. When `site` is omitted or empty, the page shows the hostname of `audience`, with no scheme and no port.

With no session, Signet shows its sign-in page. The person chooses Continue with Google, Continue with Apple, or Continue with Facebook, signs in on that site, and returns. The page lists only providers the operator has configured. When none are configured and test sign-in is off, the page shows `no-provider` and no button. That code is listed in the [administrator guide](admin.md).

With a session, Signet redirects to the return URL. The proof is in the fragment:

```text
#signet-proof=<proof>
```

The fragment is the credential. Only the page at that origin should read it.

When sign-in does not finish, the return URL's fragment is `#signet-identity=failed` and there is no proof. Send the person to `/connect` again to offer another account.

An agent does not open this page.

## Ask from an agent

The agent holds its own key and sends `POST /agent-proof`, signed with that key. Signet stores nothing about the agent. `signAgentRequest` builds the request. `agentRequestOk` checks one.

`signProof` is how the Signet process signs. Callers do not sign proofs.

## Reference client

The client asks for one proof and prints each step. It does not print the agent secret or the proof bytes.

```text
npm start -w @agenticage/client -- --agent <signet-origin> <audience> <agent-key-file> <public-key-file>
npm start -w @agenticage/client -- --human <signet-origin> <audience> <public-key-file>
```

`--human` listens on the audience. The audience must be `http://127.0.0.1:<port>` or `http://localhost:<port>`. Any other audience fails before the listen. The log says the proof would be returned to that origin.

Running the process, the keys, and the `SIGNET_` settings are in the [administrator guide](admin.md).
