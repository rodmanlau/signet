# Signet

Signet issues a short-lived signed proof so a program can tell who someone is without asking Signet.

A checker that calls Signet on every visit learns nothing the proof does not already say, and it depends on Signet being up. The proof is signed by a key that stays on the Signet machine. Callers receive the proof, not the key. The same person, or the same agent, stays the same subject for a given audience on a later visit. That stability comes from a second key, the derivation key, which also stays on the Signet machine. Replacing the derivation key makes every returning subject a new one.

One process holds both keys. A person signs in through a browser. Signet signs a proof for an audience, which is an origin, and sends the proof back to that origin. An agent signs a request with its own key. Signet checks that request and signs a proof for an audience the same way. The program that receives the proof checks the signature, the audience, and the expiry with the public key it already has. It does not call Signet to ask whether the proof is valid. A proof lasts 15 minutes.

`@agenticage/proof` is the published package for signing and checking proofs. `@agenticage/server` is the process. `@agenticage/client` asks the process for one proof. Only `@agenticage/proof` is published.

- [Administrator guide](docs/admin.md) covers keys, the process, and its settings.
- [Developer guide](docs/develop.md) covers the proof, the public key, and how to ask for one.
