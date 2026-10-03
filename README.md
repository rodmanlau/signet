# Signet

Signet issues a signed proof that lasts 15 minutes. The program that receives it checks the signature, the audience, and the expiry with Signet's public key. It does not ask Signet whether the proof is valid.

The proof names the subject, the audience it is for, the issuer, and the expiry. The signing key stays on the Signet machine. Callers receive the proof, not the key. The same person, or the same agent, keeps the same subject for a given audience. That stability comes from a second key, the derivation key, which also stays on the Signet machine. Replacing the derivation key makes every returning subject a new one.

One process holds both keys. A person signs in through a browser. An agent signs its own request. In both cases the audience is an origin, and the proof is for that origin.

`@agenticage/proof` is the published package for signing and checking proofs. `@agenticage/server` is the process. `@agenticage/client` asks the process for one proof. Only `@agenticage/proof` is published.

- [Administrator guide](docs/admin.md) — run the process, keep the keys, and configure sign-in.
- [Developer guide](docs/develop.md) — check a proof, or ask for one from a browser or an agent.
