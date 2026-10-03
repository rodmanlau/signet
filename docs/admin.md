# Administrator guide

Run this from the repository root, after `npm install`. Paths below are relative to that root. The package is `@agenticage/server`.

The signing key and the derivation key stay on this machine. Changing the address the process listens on does not mint new keys. A subject's id uses the audience's registrable domain, and the port is ignored. A leading `www` is ignored on a normal domain. `localhost` and a raw IP are used as written, so `127.0.0.1` and another address are different subjects with the same keys. Checkers must use the `identity-keys.json` from this setup. An older file with the same key id is rejected.

## Setup

The default directory is `.signet`. Setup creates it and writes:

| File | Contents |
| --- | --- |
| `private-key` | 32-byte signing key. Secret. |
| `derivation-key` | 32-byte derivation key. Secret. Different from the signing key. |
| `login.env` | The variables the process needs, including `SIGNET_TEST=1`. |
| `identity-keys.json` | The public key array a checker stores. |

```text
node scripts/setup-login.mjs
```

`.signet/` is gitignored. A second run keeps both keys and keeps `login.env`, and rewrites `identity-keys.json` from the signing key. Setup does not rewrite an existing `login.env`. An existing file still has the old names until you edit it.

Pass a directory when the keys should live somewhere else. A relative path is resolved from the repository root:

```text
node scripts/setup-login.mjs keys
```

If the keys already exist, pass that directory. Do not copy it into this repository. Do not run setup with no arguments when you mean to keep an existing directory: that mints a new key in `.signet`. A directory that already has one of the two key files and not the other is refused with `refusing to mint one key beside an existing key`.

Give checkers `identity-keys.json` and the issuer origin. They do not get `private-key`, `derivation-key`, or `login.env`.

## Start

```text
node scripts/start-login.mjs
```

Pass the same directory if you did not use the default:

```text
node scripts/start-login.mjs keys
```

The process listens on `127.0.0.1:8787` and prints that URL. Set `SIGNET_HOST` in the environment when another machine must reach Signet. Leave `SIGNET_ISSUER` unset to publish `http://<SIGNET_HOST>:<port>`, or set `SIGNET_ISSUER` when the public origin differs from the listen address. A value already in the environment wins over `login.env`. Leave it running. Stop it with Ctrl+C.

`SIGNET_TEST=1` in the generated env turns on `POST /test-login` and shows a Sign in button on the connect page. That mints a session without Google, Apple, or Facebook. Turn that off for a public host: remove the line from `login.env`, restart, and set the provider variables below. A provider with no client id has no button.

## Public host

Fly.io runs one machine from `Dockerfile` and `fly.toml`. The app name is `signet`, the region is `iad`, and the issuer is `https://signet.fly.dev`. The process listens on `0.0.0.0:8787`. Sessions are `/data/sessions.json` on that machine's volume. The machine stays up when idle. A deploy replaces that one machine. It does not add a second.

The image starts `@agenticage/server` directly. It does not read `login.env`. `SIGNET_PRIVATE_KEY` and `SIGNET_DERIVATION_KEY` are Fly secrets, the same two values already in `.signet/login.env`. Leave `SIGNET_HOST`, `SIGNET_PORT`, `SIGNET_SESSIONS`, `SIGNET_ISSUER`, and `SIGNET_TEST` out of those secrets. `SIGNET_TEST` stays unset. A provider's client id and secret are Fly secrets when that provider is used.

A push to `master` deploys after the test workflow passes. The GitHub secret `FLY_API_TOKEN` is a Fly deploy token. Pull requests run tests and do not deploy.

## Variables

`login.env` is `NAME=VALUE` lines. Blank lines and lines starting with `#` are ignored. The start script loads a name from it only when the environment has not already set that name. These are the names this process reads. A checker does not read them.

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

## Warnings

The connect page shows a warning code when nobody can choose an account because this process is not configured. The code is on the page. This table is the list.

| Code | When it appears | What to do |
| --- | --- | --- |
| `no-provider` | No provider client id is set, and `SIGNET_TEST` is not `1`. The page has no account button. | Set `SIGNET_GOOGLE_CLIENT_ID`, `SIGNET_APPLE_CLIENT_ID`, or `SIGNET_FACEBOOK_CLIENT_ID`. A client secret without its client id leaves this code in place. On the public host, deploy the secrets so the machine boots with the new values. |

Redirect URIs to register with each provider, using the issuer:

- `<issuer>/auth/google/callback`
- `<issuer>/auth/apple/callback`
- `<issuer>/auth/facebook/callback`

## What the running server offers

- `GET /connect?audience=<origin>&return=<url>` sends a browser that already has a session back to `return` with a proof in the URL fragment. The return URL's origin must equal `audience`. The session cookie is marked `Secure` on `https` and on loopback, and on any other `http` origin it is stored without that mark.
- `GET /.well-known/signet-keys` returns `{ "keys": [ { "id", "publicKey" } ] }`. Checkers store the inner array, not this whole object.
- `POST /agent-proof` is how an agent asks for a proof. The agent signs the request with its own key. This server stores nothing about that agent.
- `POST /logout` ends the browser session.

Proofs expire 15 minutes after this server signs them. Checkers accept them with the public key. They do not call back here.

`@agenticage/client` asks this process for one proof and prints each step. It does not print the agent secret or the proof bytes. See the [developer guide](develop.md).
