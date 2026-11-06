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

## Sign out or switch

Send the person to one of these. The query is the same as `/connect`: `audience`, `return`, and an optional `site`. The return URL's origin must equal `audience`.

```text
GET /sign-out?audience=<origin>&return=<url>
GET /switch?audience=<origin>&return=<url>
```

`GET /sign-out` shows `You are signed in as {label}.` and a Sign out button. The button posts back to that URL, ends the browser session, and redirects to `return` with `#signet-identity=signed-out`. With no session, the GET redirects there. The browser Back button leaves the session in place.

`GET /switch` shows the same sentence and the configured account buttons. The Google button asks Google to show its account chooser. With no session, Signet shows the sign-in page. A finished sign-in replaces the browser account and returns a proof in `#signet-proof=`. A failed sign-in redirects with `#signet-identity=failed` and leaves the account in place.

A proof the site already holds stays valid until it expires. Signet does not tell other sites.

## Ask from an agent

The agent holds its own key and sends `POST /agent-proof`, signed with that key. `signAgentRequest` builds the request. `agentRequestOk` checks one.

A key that is not on the person's grant list receives `403` with JSON `{ "error": "unauthorized", "skill": "<issuer>/agents/skill" }`. The skill text explains the next step. The agent then posts `POST /agents/ticket` with the same signed fields, a `label`, and an optional loopback origin (`http://127.0.0.1:<port>` or `http://localhost:<port>` only). The response includes an `approveUrl`. A signed-in person opens that URL and clicks Allow. That grants the agent's existing public key. Signet does not mint a new secret.

After Allow, a loopback ticket redirects to `{loopback}/#signet-agent=allowed`. Without loopback, the agent polls `POST /agent-proof` until it is `200`. Revoke is `GET /agents` while signed in, or an agent-led revoke URL for the same key. Revoke stops the next mint. A proof a site already holds stays valid until it expires.

`signProof` is how the Signet process signs. Callers do not sign proofs.

## Loopback test issuer

A local browser test can join `http://127.0.0.1:8080` without a person. The loopback issuer is a separate process. It signs that audience only, with its own signing key and its own derivation key. Check the proof with `verifyProof`. Pass this process's origin as `issuer`, `http://127.0.0.1:8080` as `audience`, and the public key from its `identity-keys.json`.

```text
node scripts/setup-loopback.mjs
node scripts/start-loopback.mjs
```

Setup writes `.signet-loopback/`. The process listens on `127.0.0.1:8790`. Its issuer origin is `http://127.0.0.1:8790`. It refuses another listen address, a public issuer, port `8080`, and an environment that has `SIGNET_PRIVATE_KEY`, `SIGNET_DERIVATION_KEY`, or `SIGNET_TEST`.

Open the same connect URL a browser would open against Signet:

```text
GET /connect?audience=http://127.0.0.1:8080&return=http://127.0.0.1:8080/
```

The return URL's origin must be `http://127.0.0.1:8080`. The page redirects there with `#signet-proof=`. Any other audience is `400` `rejected`. There is no session, no provider, and no `/test-login`. `GET /.well-known/signet-keys` returns this process's public key.

Every proof from one derivation key names the same subject. The provider is `google` and the subject is `local`. Clients on `http://127.0.0.1:8080` that trust this issuer all see that subject. A later proof from the same keys is the same subject with a new 15-minute expiry.

A public origin needs a proof from production Signet. This issuer will not sign one. A proof it already signed fails `verifyProof` when the audience or the issuer differs, including when the audience is a public origin and when the issuer is `https://signet.fly.dev`.

```text
npm start -w @agenticage/client -- --human http://127.0.0.1:8790 http://127.0.0.1:8080 .signet-loopback/identity-keys.json
```

## Reference client

The client prints each step. It does not print the agent secret or the proof bytes.

```text
npm start -w @agenticage/client -- --agent <signet-origin> <audience> <agent-key-file> <public-key-file> [--label <name>]
npm start -w @agenticage/client -- --human <signet-origin> <audience> <public-key-file>
npm start -w @agenticage/client -- --sign-out <signet-origin> <audience>
npm start -w @agenticage/client -- --switch <signet-origin> <audience> <public-key-file>
```

A granted key gets a proof from the first `POST /agent-proof`. When that response is 403 and the JSON error is `unauthorized`, the client prints the `skill` URL from the body. It listens on `127.0.0.1` and prints an approve URL. The label defaults to `signet-client`. `--label` sets another name. After Allow, the browser opens that listener with `#signet-agent=allowed`. The client then requests the proof again.

`--human` listens on the audience. The audience must be `http://127.0.0.1:<port>` or `http://localhost:<port>`. Any other audience fails before the listen. The log says the proof would be returned to that origin.

`--sign-out` listens the same way and opens `/sign-out`. The log ends with `Redirect. #signet-identity=signed-out`. `--switch` listens the same way and opens `/switch`. A proof is checked the same way as `--human`.

Running the process, the keys, and the `SIGNET_` settings are in the [administrator guide](admin.md).
