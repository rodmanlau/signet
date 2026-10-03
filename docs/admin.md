# Administrator guide

Run Signet from the repository root, after `npm install`. Paths below are relative to that root. The package is `@agenticage/server`.

The signing key and the derivation key stay on this machine. Changing the address the process listens on does not mint new keys. A subject is stable for an audience: Signet uses the audience's registrable domain and ignores the port. A leading `www` is ignored on a normal domain. `localhost` and a raw IP are used as written, so `127.0.0.1` and another address are different subjects even with the same keys.

## Create keys

The default directory is `.signet`. Setup creates it and writes:

| File | Contents |
| --- | --- |
| `private-key` | 32-byte signing key. Secret. |
| `derivation-key` | 32-byte derivation key. Secret. Different from the signing key. |
| `login.env` | Settings for the process, including `SIGNET_TEST=1`. |
| `identity-keys.json` | Public keys. The program that checks proofs stores this file. |

```text
node scripts/setup-login.mjs
```

`.signet/` is gitignored. A second run keeps both keys and keeps `login.env`, and rewrites `identity-keys.json` from the signing key. Setup leaves an existing `login.env` unchanged. If that file still names settings this process does not read, edit it yourself.

Pass a directory when the keys should live somewhere else. A relative path is resolved from the repository root:

```text
node scripts/setup-login.mjs keys
```

When the keys already exist, pass that directory. Keep the directory out of this repository. Setup with no arguments uses `.signet`, and mints a new key pair there when that directory has none. A directory that has one of the two key files and not the other stops with `refusing to mint one key beside an existing key`.

Give each program that checks proofs `identity-keys.json` and the issuer origin. An older file that reuses a key id with a different public key is rejected. Those programs do not receive `private-key`, `derivation-key`, or `login.env`.

## Start

```text
node scripts/start-login.mjs
```

Pass the same directory when you did not use the default:

```text
node scripts/start-login.mjs keys
```

The process listens on `127.0.0.1:8787` and prints that URL. Set `SIGNET_HOST` in the environment when another machine must reach it. Leave `SIGNET_ISSUER` unset to publish `http://<SIGNET_HOST>:<port>`. Set `SIGNET_ISSUER` when the public origin differs from the listen address. A value already in the environment wins over `login.env`. Leave the process running. Stop it with Ctrl+C.

The generated `login.env` sets `SIGNET_TEST=1`. That adds a passwordless Sign in form on the sign-in page and accepts `POST /test-login`. Remove that line and restart before anyone else can reach the process.

## Sign-in

A browser without a session gets the sign-in page. Configured providers appear in this order: Continue with Google, Continue with Apple, Continue with Facebook. A button is shown when its client id is a non-empty value. A secret alone does not add a button, and a client id of only spaces does not count.

Register these redirect URIs with the provider. `<issuer>` is the `SIGNET_ISSUER` origin, with no path:

- `<issuer>/auth/google/callback`
- `<issuer>/auth/apple/callback`
- `<issuer>/auth/facebook/callback`

Apple's client secret is a JWT. This process does not mint it.

On the public host, set each client id and secret as a Fly secret, then deploy the secrets so the machine boots with them. Saving a secret in the dashboard only stages it. The running machine keeps the previous environment until that deploy.

### Warnings

The sign-in page prints a code when it cannot offer an account.

| Code | When it appears | What to do |
| --- | --- | --- |
| `no-provider` | No provider client id is set, and `SIGNET_TEST` is not `1`. The page says `Sign-in is not set up.` and shows no account button. | Set `SIGNET_GOOGLE_CLIENT_ID`, `SIGNET_APPLE_CLIENT_ID`, or `SIGNET_FACEBOOK_CLIENT_ID`. A client secret without its client id leaves the code in place. On the public host, deploy the secrets so the machine boots with them. |

## Public host

Fly.io runs one machine from `Dockerfile` and `fly.toml`. The app name is `signet`, the region is `iad`, and the issuer is `https://signet.fly.dev`. The process listens on `0.0.0.0:8787`. Sessions are `/data/sessions.json` on that machine's volume. The machine stays up when idle. A deploy restarts that one machine. It does not add a second.

The process reads the session file when it starts and rewrites the file when a session changes. A second machine would not see those sessions.

The image starts `@agenticage/server` directly and does not read `login.env`. Set `SIGNET_PRIVATE_KEY` and `SIGNET_DERIVATION_KEY` as Fly secrets, using the values in `.signet/login.env`. Leave `SIGNET_HOST`, `SIGNET_PORT`, `SIGNET_SESSIONS`, `SIGNET_KEY_ID`, `SIGNET_ISSUER`, and `SIGNET_TEST` out of the secrets. `fly.toml` sets the host, port, session path, key id, and issuer. `SIGNET_TEST` stays unset.

A push to `master` deploys after the test workflow passes. The GitHub secret `FLY_API_TOKEN` is a Fly deploy token. Pull requests run tests and do not deploy.

## Variables

`login.env` is `NAME=VALUE` lines. Blank lines and lines that start with `#` are ignored. The start script reads a name from the file only when the environment has not already set it. A program that checks proofs does not read these names.

| Variable | Required | Meaning |
| --- | --- | --- |
| `SIGNET_SESSIONS` | yes | Path of the session file. The directory is created when the first session is saved. The process loads the file at startup, so a person stays signed in across a restart while the file remains. |
| `SIGNET_PRIVATE_KEY` | yes | Signing key, standard base64 of 32 bytes. |
| `SIGNET_DERIVATION_KEY` | yes | Derivation key, standard base64 of 32 bytes. It must differ from the signing key. |
| `SIGNET_PORT` | no | Listen port. Default `8787`. Set it in the environment. |
| `SIGNET_HOST` | no | Listen address. Default `127.0.0.1`. Set it in the environment. |
| `SIGNET_KEY_ID` | no | Default `k1`. This is the `id` in `identity-keys.json`. |
| `SIGNET_ISSUER` | no | Public origin. Default `http://<SIGNET_HOST>:<port>`. An `http` or `https` origin with no path. Set it in the environment when the public origin differs from the listen address. |
| `SIGNET_TEST` | no | `1` enables `POST /test-login` and the Sign in form. A generated file includes this line. Leave it unset on a public host. |
| `SIGNET_GOOGLE_CLIENT_ID` | no | Shows Continue with Google. |
| `SIGNET_GOOGLE_CLIENT_SECRET` | with the client id | Google client secret. Used when Google redirects back. |
| `SIGNET_APPLE_CLIENT_ID` | no | Shows Continue with Apple. |
| `SIGNET_APPLE_CLIENT_SECRET` | with the client id | Apple client secret. A JWT this process does not mint. |
| `SIGNET_FACEBOOK_CLIENT_ID` | no | Shows Continue with Facebook. |
| `SIGNET_FACEBOOK_CLIENT_SECRET` | with the client id | Facebook client secret. Used when Facebook redirects back. |

A generated file writes the two keys, the session path, the key id, and `SIGNET_TEST`. It does not write the host, the port, or the issuer.

## Routes

Proofs expire 15 minutes after Signet signs them. Checking one is covered in the [developer guide](develop.md).

| Request | Result |
| --- | --- |
| `GET /` | `404` and the text `not found`. |
| `GET /.well-known/signet-keys` | `{ "keys": [ { "id", "publicKey" } ] }`. Store the inner array. |
| `GET /connect?audience=<origin>&return=<url>` | Optional `site` is the name shown on the page. A non-empty value replaces the audience hostname. Without a session, the response is the sign-in page. With a session, Signet shows a short confirmation, then redirects to `return` with the proof in `#signet-proof=`. The return URL's origin must equal `audience`. A failed sign-in redirects to `return` with `#signet-identity=failed`. |
| `GET /sign-out?audience=<origin>&return=<url>` | Optional `site`. With a session, the page says `You are signed in as {label}.` and its button posts to this URL. The POST ends the browser session and redirects to `return` with `#signet-identity=signed-out`. With no session, the GET redirects there. The return URL's origin must equal `audience`. |
| `POST /sign-out?audience=<origin>&return=<url>` | Returns `303` and the body `signed-out`. The fragment is `#signet-identity=signed-out`, replacing any fragment. It clears the session cookie and the OAuth cookie. With no session it redirects the same way. A return origin other than `audience` is `400` `rejected` with no `Location`. |
| `GET /switch?audience=<origin>&return=<url>` | Optional `site`. With a session, the page says `You are signed in as {label}.` and offers the configured account buttons. The Google button asks Google to show its account chooser. With no session, the response is the sign-in page. A finished sign-in replaces the browser account and returns a proof in `#signet-proof=`. A failed sign-in redirects with `#signet-identity=failed` and leaves the account in place. |
| `POST /agent-proof` | An agent asks for a proof and signs the request with its own key. This server stores nothing about that agent. |
| `POST /logout` | Ends the browser session. |

The session cookie lasts 400 days. It is marked `Secure` for an `https` issuer and for loopback. For any other `http` issuer it is stored without that mark.

`@agenticage/client` asks this process for one proof, or sends the browser to sign out or to switch accounts, and prints each step. It does not print the agent secret or the proof bytes. See the [developer guide](develop.md).
