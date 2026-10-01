# Developer guide

`@agenticage/proof` signs and checks proofs. Install that published package. This repository's server and client are private.

A proof is a signed set of claims: `keyId`, `issuer`, `identity`, `audience`, `issuedAt`, and `expiresAt`. `audience` and `issuer` are origins. `identity` is the stable subject for that audience. The signature is from the signing key on the Signet machine.

Check a proof locally with `verifyProof` and the public keys you were given. Match `audience` to the origin you serve, and match `issuer` and `keyId` to the key you trust. The clock may be 60 seconds off in either direction. After that window, or after `expiresAt`, the proof is rejected. `readProofAudience` and `readProofExpiry` read those two fields without verifying. Verifying does not call Signet.

The same person, or the same agent, gets the same `identity` for an audience on a later visit. The subject is derived from the audience's registrable domain. The port is ignored. A leading `www` is ignored on a normal domain. `localhost` and a raw IP are used as written, so `127.0.0.1` and another address are different subjects.

## Public keys

`GET /.well-known/signet-keys` on the Signet origin returns `{ "keys": [ { "id", "publicKey" } ] }`. Store the inner array. That array is also the file `identity-keys.json` from setup. An older file that reuses a key id with a different public key is rejected.

## Asking for a proof

A person uses a browser:

`GET /connect?audience=<origin>&return=<url>`

`audience` is your origin. The return URL's origin must equal `audience`. Signet redirects there with the proof in the URL fragment. The fragment is the credential. Only that origin should receive it.

An agent holds its own key and `POST`s `/agent-proof`. It signs the request with that key. Signet stores nothing about the agent. `signAgentRequest` builds that request. `agentRequestOk` checks one.

`signProof` is how the Signet process signs. Callers do not sign proofs themselves.

The reference client asks for one proof and prints each step. It does not print the agent secret or the proof bytes.

```text
npm start -w @agenticage/client -- --agent <signet-origin> <audience> <agent-key-file> <public-key-file>
npm start -w @agenticage/client -- --human <signet-origin> <audience> <public-key-file>
```

`--human` listens on the audience. The audience must be `http://127.0.0.1:<port>` or `http://localhost:<port>`. Any other audience fails before the listen, and the log says the proof would be returned to that origin.

Running the process, the keys, and `SIGNET_` settings are in the [administrator guide](admin.md).
