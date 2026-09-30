# Run Signet

This process is Signet, the proof issuer. Browsers and machine clients come here to get a proof. World servers never call it to ask who someone is. They keep a copy of the public key and check the proof themselves. The package is `@signet/server`.

One Signet origin serves every worldsite. The signing key and the derivation key stay on this machine. The derivation key is how a person or an agent stays the same person on a later visit. Replacing it gives every world a stranger. The setup script will not replace a key that is already there.

Changing the address this process listens on does not mint new keys. A person's id uses the world's registrable domain, and the port is ignored. A leading `www` is ignored on a normal domain. `localhost` and a raw IP are used as written, so `127.0.0.1` and another address are different people with the same keys. Worlds must use the `identity-keys.json` from this setup. An older file with the same key id is rejected.

## Setup

Keys that already exist stay in their directory. Do not copy that directory into this repository. Do not run setup with no arguments when those keys exist: that would mint a second key in this repo. The first start from this repository is pointed at the directory that already holds them. On this machine that directory is `C:\Users\rodma\src\valar\.valar\login`:

```text
node scripts/setup-login.mjs C:\Users\rodma\src\valar\.valar\login
node scripts/start-login.mjs C:\Users\rodma\src\valar\.valar\login
```

Setup keeps the signing key, the derivation key, and `login.env` there. It rewrites `identity-keys.json` from the signing key. A directory that already has one of the two key files and not the other is refused with `refusing to mint one key beside an existing key`.

From the repository root, after `npm install`:

```text
node scripts/setup-login.mjs
```

That creates `.valar/login/` and writes:

| File | Contents |
| --- | --- |
| `private-key` | 32-byte signing key. Secret. |
| `derivation-key` | 32-byte derivation key. Secret. Different from the signing key. |
| `login.env` | The variables the process needs, including `SIGNET_TEST=1`. |
| `identity-keys.json` | The public key array world servers put in `WORLD_SIGNET_KEYS`. |

`.valar/` is gitignored. A second run keeps both keys and keeps `login.env`, and rewrites `identity-keys.json` from the signing key. Setup does not rewrite an existing `login.env`. An existing file still has the old names until you edit it. Pass a directory to put the files somewhere else:

```text
node scripts/setup-login.mjs D:\valar-login
```

Give world operators `identity-keys.json` and the issuer origin. They do not get `private-key`, `derivation-key`, or `login.env`.

## Start

```text
node scripts/start-login.mjs
```

Pass the same directory if you did not use the default. The process listens on `127.0.0.1:8787` and prints that URL. Set `SIGNET_HOST` in the environment when another machine must reach Signet. Leave `SIGNET_ISSUER` unset to publish `http://<SIGNET_HOST>:<port>`, or set `SIGNET_ISSUER` when the public origin differs from the listen address. A value already in the environment wins over `login.env`. Leave it running. Stop it with Ctrl+C.

`SIGNET_TEST=1` in the generated env turns on `POST /test-login` and shows a Sign in button on the connect page. That mints a session without Google, Apple, or Facebook. Turn that off for a public Signet host: remove the line from `login.env`, restart, and set the provider variables below. A provider with no client id has no button.

## Variables

`login.env` is `NAME=VALUE` lines. Blank lines and lines starting with `#` are ignored. The start script loads a name from it only when the environment has not already set that name. These are the names this process reads from its environment. The world process does not read them. Which process reads which name is in [the guide index](README.md).

| Variable | Required | Meaning |
| --- | --- | --- |
| `SIGNET_SESSIONS` | yes | Path of the session file. The directory is created when the first session is saved. People stay signed in across restarts while this file remains. |
| `SIGNET_PRIVATE_KEY` | yes | Signing key, standard base64 of 32 bytes. |
| `SIGNET_DERIVATION_KEY` | yes | Derivation key, standard base64. It must differ from the signing key. |
| `SIGNET_PORT` | no | Default `8787`. Set it in the environment. |
| `SIGNET_HOST` | no | Address the process listens on. Omitted, it is `127.0.0.1`. Set it in the environment. |
| `SIGNET_KEY_ID` | no | Default `k1`. This id is the `id` inside `identity-keys.json`. |
| `SIGNET_ISSUER` | no | Default `http://<SIGNET_HOST>:<port>`. It must be an `http` or `https` origin with no path. Set it in the environment when the public origin differs from the listen address. |
| `SIGNET_TEST` | no | `1` enables `POST /test-login` and the Sign in button. A generated file includes this line. Leave it unset on a public host. |
| `SIGNET_GOOGLE_CLIENT_ID` | no | Shows the Google button. |
| `SIGNET_GOOGLE_CLIENT_SECRET` | with the id | Google client secret. |
| `SIGNET_APPLE_CLIENT_ID` | no | Shows the Apple button. |
| `SIGNET_APPLE_CLIENT_SECRET` | with the id | Apple client secret. This process does not mint that JWT. |
| `SIGNET_FACEBOOK_CLIENT_ID` | no | Shows the Facebook button. |
| `SIGNET_FACEBOOK_CLIENT_SECRET` | with the id | Facebook client secret. |

A generated file writes the secrets, the session path, the key id, and `SIGNET_TEST`, and does not write host, port, or issuer.

Redirect URIs to register with each provider, using your issuer:

- `<issuer>/auth/google/callback`
- `<issuer>/auth/apple/callback`
- `<issuer>/auth/facebook/callback`

## What the running server offers

- `GET /connect?audience=<origin>&return=<url>` sends a browser that already has a session back to that world with a proof in the URL fragment. The return URL's origin must equal `audience`. The session cookie is marked `Secure` on `https` and on loopback, and on any other `http` origin it is stored without that mark.
- `GET /.well-known/signet-keys` returns `{ "keys": [ { "id", "publicKey" } ] }`. World servers store the inner array, not this whole object. `GET /.well-known/valar-keys` is not served.
- `POST /agent-proof` is how a machine client asks for a proof. The machine signs the request with its own key. This server stores nothing about that agent.
- `POST /logout` ends the browser session.

Proofs expire 15 minutes after this server signs them. Worlds accept them with the public key. They do not call back here.

## Ask for one proof

`@signet/client` asks this Signet for one proof and prints each step. It does not open a world socket, and it does not print the agent secret or the proof bytes.

```text
npm start -w @signet/client -- --agent <signet-origin> <audience> <agent-key-file> <public-key-file>
npm start -w @signet/client -- --human <signet-origin> <audience> <public-key-file>
```

`--human` listens on the audience. The audience must be `http://127.0.0.1:<port>` or `http://localhost:<port>`. Any other audience fails before the listen, and the log says the proof would be returned to that origin.
