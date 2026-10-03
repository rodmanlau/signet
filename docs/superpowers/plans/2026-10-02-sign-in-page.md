# Sign-in page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the bare provider names on `GET /connect` with a sign-in page that names the returning host, offers equal `Continue with` buttons, and shows warning `no-provider` when nothing is configured.

**Architecture:** `destinationName` in `packages/server/src/connect.ts` turns the audience origin, or a non-empty `site`, into the text both pages show. `providersPage` in `packages/server/src/main.ts` renders that text and links to the existing `/auth/{provider}` routes. Official marks live in `packages/server/assets/` and are served only at `/marks/google.svg`, `/marks/apple.svg`, and `/marks/facebook.svg`. The proof, the session cookie, and the provider token exchange stay as they are.

**Tech Stack:** Node 22, TypeScript, `tsx`, Vitest, the existing `startLogin` test server. No provider SDK and no new dependency.

**Spec:** `docs/superpowers/specs/2026-10-02-sign-in-page-design.md`

## Global Constraints

- The destination name is the hostname of the `audience` origin, with no scheme and no port. A non-empty `site` replaces that hostname. An empty `site` does not. The page source contains no fixed host.
- Insert the destination name and every provider label as escaped text. Escape `&`, `<`, `>`, `"`, and `'`.
- Button labels are exactly `Continue with Google`, `Continue with Apple`, and `Continue with Facebook`, in that order. A provider with a blank client id is absent.
- Buttons are Signet links to `/auth/{provider}` with the request's `audience`, `return`, and `site`. They do not load a provider SDK or a provider webfont.
- Marks are the official files, served by this process from `/marks/{provider}.svg`. Do not redraw them, recolor them, or copy one from a web search. Do not hotlink the provider's site.
- Google's mark is the standard color G from [Sign in with Google Branding Guidelines](https://developers.google.com/identity/branding-guidelines). Apple's mark is the official Apple logo from [Sign in with Apple](https://developer.apple.com/sign-in-with-apple) and [the button guidelines](https://developer.apple.com/design/human-interface-guidelines/sign-in-with-apple). Do not use Sign in with Apple JS. Facebook's mark is the current "f" from [Facebook brand resources](https://www.meta.com/brand/resources/facebook/logo/), Facebook blue `#1877F2` with a white "f", per [Facebook Login user experience](https://developers.facebook.com/docs/facebook-login/userexperience). The Facebook pack requires a person to accept terms. If `packages/server/assets/facebook.svg` or `packages/server/assets/apple.svg` is missing, stop and ask for that file.
- With no provider and test login off, the page shows `Sign in`, `Sign-in is not set up.`, and `no-provider`, and no account button. A configured page does not contain `no-provider`.
- Test login still renders `<button type="submit">Sign in</button>` posting to `/test-login`. A public host leaves `SIGNET_TEST` unset.
- After success, the sentence is `Signed in as {label}. Taking you back to {destination}.` The one-second return and the `#signet-proof=` fragment stay. Failure still redirects with `#signet-identity=failed`.
- `POST /agent-proof` is unchanged. The shell is PowerShell: do not use `&&`. Write commit messages with UTF-8 no BOM and `git commit -F`.

## Review Focus

- A `site` value of `<Friends & co>` is shown as text, not parsed as HTML. The sign-in page task asserts the escaped sentence.
- An empty `site` parameter still shows the audience hostname. The destination-name task asserts `connectingText` and the page task asserts the HTML.
- An audience of `http://192.0.2.10:8080` shows `192.0.2.10`, not the port. The destination-name task asserts this.
- A client id of spaces is not configured, so the page shows `no-provider`. The sign-in page task asserts this.
- A mark request other than the three exact paths, including `/marks/../package.json`, is a 404 and does not read another file. The marks task asserts this.

---

### Task 1: Serve the three official marks

**Files:**
- Create: `packages/server/assets/google.svg`
- Create: `packages/server/assets/apple.svg`
- Create: `packages/server/assets/facebook.svg`
- Modify: `packages/server/src/main.ts` (the `handle` function around the final 404, and a new `handleMark`)
- Test: `packages/server/test/connect.test.ts`

**Interfaces:**
- Consumes: `startLogin` from `packages/server/src/main.ts`, already used by the tests.
- Produces: `GET /marks/google.svg`, `GET /marks/apple.svg`, and `GET /marks/facebook.svg` return the file bytes with `content-type: image/svg+xml`. Any other `/marks/` path returns 404 `not found`. Later tasks put `src="/marks/{provider}.svg"` on each button.

- [ ] **Step 1: Write the failing test**

Add this test inside `describe('login origin')` in `packages/server/test/connect.test.ts`. `startLogin`, `generateKeyPair`, and `tempSessions` are already in that file.

```ts
it('serves only the three official marks', async () => {
  const { secretKey, publicKey } = await generateKeyPair()
  const sessions = await tempSessions()
  const server = await startLogin({
    port: 0,
    issuer: 'https://login.example',
    keyId: 'k1',
    privateKey: secretKey,
    publicKey,
    derivationKey: new TextEncoder().encode('0123456789abcdef0123456789abcdef'),
    now: () => 1_700_000_000,
    testLogin: false,
    providers: {},
    sessionsFile: sessions.file,
  })
  try {
    for (const name of ['google', 'apple', 'facebook']) {
      const mark = await fetch(new URL(`/marks/${name}.svg`, server.url))
      expect(mark.status).toBe(200)
      expect(mark.headers.get('content-type')).toContain('image/svg+xml')
      expect(await mark.text()).toContain('<svg')
    }
    const missing = await fetch(new URL('/marks/other.svg', server.url))
    expect(missing.status).toBe(404)
    expect(await missing.text()).toBe('not found')
    const escaped = await fetch(new URL('/marks/../package.json', server.url))
    expect(escaped.status).toBe(404)
  } finally {
    await server.close()
    await sessions.remove()
  }
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run packages/server/test/connect.test.ts -t "serves only the three official marks"`

Expected: FAIL. The three mark URLs are 404.

- [ ] **Step 3: Put the official files in the repo**

Download Google's pre-approved icons to a temp directory, not the repo:

```powershell
Invoke-WebRequest -Uri "https://developers.google.com/static/identity/images/signin-assets.zip" -OutFile "$env:TEMP\signin-assets.zip"
Expand-Archive -Path "$env:TEMP\signin-assets.zip" -DestinationPath "$env:TEMP\signin-assets" -Force
```

Copy the one SVG that is the standard color G by itself, not a full button that already contains words, to `packages/server/assets/google.svg`. Delete the temp zip and the extracted directory. Do not commit them.

Apple and Facebook do not have a stable file URL. If `packages/server/assets/apple.svg` or `packages/server/assets/facebook.svg` is missing, stop this task and ask for those two official files. Do not draw a logo, and do not download an "f" or an Apple logo from a search. Continue only after both files are in those paths and each file contains an `<svg` root.

Confirm `.dockerignore` does not exclude `packages/server/assets` or `*.svg`. The Dockerfile's `COPY . .` already includes that directory. Do not edit the Dockerfile.

- [ ] **Step 4: Serve the three paths**

In `packages/server/src/main.ts`, add `fileURLToPath` to the existing `node:url` import.

Add this above `handle`, and call it from `handle` immediately before the final `sendText(res, 404, 'not found')`:

```ts
const MARK_FILES = {
  google: fileURLToPath(new URL('../assets/google.svg', import.meta.url)),
  apple: fileURLToPath(new URL('../assets/apple.svg', import.meta.url)),
  facebook: fileURLToPath(new URL('../assets/facebook.svg', import.meta.url)),
} as const

async function handleMark(req: IncomingMessage, res: ServerResponse, provider: ProviderName): Promise<void> {
  if (req.method !== 'GET') return sendText(res, 405, 'method not allowed', { allow: 'GET' })
  const bytes = await readFile(MARK_FILES[provider])
  res.writeHead(200, {
    'content-type': 'image/svg+xml',
    'content-length': String(bytes.length),
    'cache-control': 'no-store',
  })
  res.end(bytes)
}
```

Inside `handle`:

```ts
const mark = /^\/marks\/(google|apple|facebook)\.svg$/.exec(path)
if (mark && isProvider(mark[1])) return await handleMark(req, res, mark[1])
```

`isProvider` already accepts only those three names. The route does not read `req.url` as a filesystem path.

- [ ] **Step 5: Run the test to verify it passes**

Run: `npx vitest run packages/server/test/connect.test.ts -t "serves only the three official marks"`

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
[System.IO.File]::WriteAllText("$env:TEMP\signet-commit.txt", "Serve the official provider marks from Signet.`n`nThe sign-in buttons need a same-origin Google, Apple, and Facebook mark, and no other path under /marks can read a file.`n", (New-Object System.Text.UTF8Encoding $false))
git add packages/server/assets/google.svg packages/server/assets/apple.svg packages/server/assets/facebook.svg packages/server/src/main.ts packages/server/test/connect.test.ts
git commit -F "$env:TEMP\signet-commit.txt"
Remove-Item "$env:TEMP\signet-commit.txt"
```

### Task 2: Name the returning host in the success sentence

**Files:**
- Modify: `packages/server/src/connect.ts` (`connectingText`, new `destinationName`)
- Test: `packages/server/test/connect.test.ts`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `destinationName(audience: string, site?: string): string` and the new `connectingText` sentence. Task 3 calls `destinationName` with `query.audience` and `query.site`. `site` of `undefined` or `''` uses the hostname. Any other string is returned unchanged. `connectingText` returns `Signed in as ${label}. Taking you back to ${destinationName(audience, site)}.`

- [ ] **Step 1: Write the failing tests and update the old sentences**

In `packages/server/test/connect.test.ts`, change the import to:

```ts
import { connectingText, decideAgentProof, decideConnect, destinationName } from '../src/connect.js'
```

Replace the two `connectingText` expectations in `refuses a return origin that is not the audience` with:

```ts
expect(destinationName('https://friends.example')).toBe('friends.example')
expect(destinationName('https://friends.example', '')).toBe('friends.example')
expect(destinationName('https://friends.example', 'Friends')).toBe('Friends')
expect(destinationName('http://192.0.2.10:8080')).toBe('192.0.2.10')
expect(connectingText('https://friends.example', 'ada@gmail.com')).toBe(
  'Signed in as ada@gmail.com. Taking you back to friends.example.',
)
expect(connectingText('https://friends.example', 'ada@gmail.com', 'Friends')).toBe(
  'Signed in as ada@gmail.com. Taking you back to Friends.',
)
expect(connectingText('https://friends.example', 'ada@gmail.com', '')).toBe(
  'Signed in as ada@gmail.com. Taking you back to friends.example.',
)
expect(connectingText('http://192.0.2.10:8080', 'Ada')).toBe(
  'Signed in as Ada. Taking you back to 192.0.2.10.',
)
```

Replace every remaining old sentence in that file:

- `Connecting to https://friends.example (Friends) as ada@gmail.com` becomes `Signed in as ada@gmail.com. Taking you back to Friends.`
- `Connecting to https://friends.example as Ada` becomes `Signed in as Ada. Taking you back to friends.example.`
- `Connecting to http://192.0.2.10:8080 as Local` becomes `Signed in as Local. Taking you back to 192.0.2.10.`

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run packages/server/test/connect.test.ts -t "refuses a return origin"`

Expected: FAIL because `destinationName` is not exported.

- [ ] **Step 3: Implement the destination name**

In `packages/server/src/connect.ts`, replace `connectingText` with:

```ts
export function destinationName(audience: string, site?: string): string {
  if (site !== undefined && site.length > 0) return site
  return new URL(audience).hostname
}

export function connectingText(audience: string, label: string, site?: string): string {
  return `Signed in as ${label}. Taking you back to ${destinationName(audience, site)}.`
}
```

Do not import `destinationName` from `main.ts` in this task. Task 3 adds that import when the page calls it.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npx vitest run packages/server/test/connect.test.ts`

Expected: PASS. The callback page and the already-signed-in `/connect` page both use `connectingText`, so the updated sentences cover them. `#signet-proof=` and `#signet-identity=failed` stay as they were.

- [ ] **Step 5: Commit**

```powershell
[System.IO.File]::WriteAllText("$env:TEMP\signet-commit.txt", "Name the returning host in the success sentence.`n`nThe page tells a person where they are going back to, using the audience hostname or a non-empty site name, and it no longer prints the whole origin.`n", (New-Object System.Text.UTF8Encoding $false))
git add packages/server/src/connect.ts packages/server/test/connect.test.ts
git commit -F "$env:TEMP\signet-commit.txt"
Remove-Item "$env:TEMP\signet-commit.txt"
```

### Task 3: Render the sign-in page

**Files:**
- Modify: `packages/server/src/main.ts` (`providersPage`, around line 442)
- Modify: `packages/server/test/connect.test.ts`
- Check: `docs/admin.md` (the Warnings table already lists `no-provider`; leave it if it matches)

**Interfaces:**
- Consumes: `destinationName(audience, site)` from Task 2. `GET /marks/{provider}.svg` from Task 1. `configured`, `authPath`, `escapeHtml`, `testLoginForm`, `NAMES`, and `PROVIDERS` already in `main.ts`.
- Produces: the HTML document described in the spec. No new export.

- [ ] **Step 1: Write the failing test**

Add this test inside `describe('login origin')`:

```ts
it('tells the person how to sign in', async () => {
  const { secretKey, publicKey } = await generateKeyPair()
  const derivationKey = new TextEncoder().encode('0123456789abcdef0123456789abcdef')
  const sessions = await tempSessions()
  const server = await startLogin({
    port: 0,
    issuer: 'https://login.example',
    keyId: 'k1',
    privateKey: secretKey,
    publicKey,
    derivationKey,
    now: () => 1_700_000_000,
    testLogin: false,
    sessionsFile: sessions.file,
    providers: {
      google: { clientId: 'google-client', exchange: async () => ({ subject: 's', label: 'Ada' }) },
      apple: { clientId: 'apple-client', exchange: async () => ({ subject: 's', label: 'Ada' }) },
      facebook: { clientId: 'facebook-client', exchange: async () => ({ subject: 's', label: 'Ada' }) },
    },
  })
  try {
    const connect = new URL('/connect', server.url)
    connect.searchParams.set('audience', 'https://friends.example')
    connect.searchParams.set('return', 'https://friends.example/room')
    const page = await fetch(connect)
    expect(page.status).toBe(200)
    const html = await page.text()
    expect(html).toContain('<title>Sign in</title>')
    expect(html).toContain('<h1>Sign in</h1>')
    expect(html).toContain(
      'To continue to friends.example, choose an account. You sign in on that site, then come back here.',
    )
    expect(html).not.toContain('no-provider')
    const google = html.indexOf('Continue with Google')
    const apple = html.indexOf('Continue with Apple')
    const facebook = html.indexOf('Continue with Facebook')
    expect(google).toBeGreaterThan(-1)
    expect(apple).toBeGreaterThan(google)
    expect(facebook).toBeGreaterThan(apple)
    expect(html).toContain('src="/marks/google.svg"')
    expect(html).toContain('src="/marks/apple.svg"')
    expect(html).toContain('src="/marks/facebook.svg"')
    expect(html).not.toContain('https://developers.google.com')
    expect(html).not.toContain('https://appleid.apple.com')
    expect(html).not.toContain('https://www.facebook.com')
    expect(html).toContain('/auth/google?')
    expect(html).toContain('audience=https%3A%2F%2Ffriends.example')
    expect(html).toContain('return=https%3A%2F%2Ffriends.example%2Froom')
    expect(html).toContain('width="20" height="20"')
    expect(html).toContain('alt=""')
    expect(html).toContain('width:320px')
    expect(html).toContain('height:40px')

    const named = new URL('/connect', server.url)
    named.searchParams.set('audience', 'https://friends.example')
    named.searchParams.set('return', 'https://friends.example/room')
    named.searchParams.set('site', '<Friends & co>')
    const namedHtml = await (await fetch(named)).text()
    expect(namedHtml).toContain('To continue to &lt;Friends &amp; co&gt;, choose an account.')
    expect(namedHtml).not.toContain('To continue to <Friends')
    expect(namedHtml).not.toContain('friends.example, choose an account')

    const blankSite = new URL('/connect', server.url)
    blankSite.searchParams.set('audience', 'http://192.0.2.10:8080')
    blankSite.searchParams.set('return', 'http://192.0.2.10:8080/')
    blankSite.searchParams.set('site', '')
    const blankHtml = await (await fetch(blankSite)).text()
    expect(blankHtml).toContain('To continue to 192.0.2.10, choose an account.')
    expect(blankHtml).not.toContain('192.0.2.10:8080, choose an account')
  } finally {
    await server.close()
    await sessions.remove()
  }
})
```

Add a second test for the empty and single-provider cases:

```ts
it('warns no-provider when no account button can be shown', async () => {
  const { secretKey, publicKey } = await generateKeyPair()
  const derivationKey = new TextEncoder().encode('0123456789abcdef0123456789abcdef')
  const sessions = await tempSessions()
  const open = async (providers: Record<string, { clientId: string; exchange: () => Promise<{ subject: string; label: string }> }>, testLogin: boolean) => {
    const server = await startLogin({
      port: 0,
      issuer: 'https://login.example',
      keyId: 'k1',
      privateKey: secretKey,
      publicKey,
      derivationKey,
      now: () => 1_700_000_000,
      testLogin,
      providers,
      sessionsFile: sessions.file,
    })
    const connect = new URL('/connect', server.url)
    connect.searchParams.set('audience', 'https://friends.example')
    connect.searchParams.set('return', 'https://friends.example/room')
    const html = await (await fetch(connect)).text()
    await server.close()
    return html
  }
  try {
    const exchange = async () => ({ subject: 's', label: 'Ada' })
    const empty = await open({}, false)
    expect(empty).toContain('<h1>Sign in</h1>')
    expect(empty).toContain('Sign-in is not set up.')
    expect(empty).toContain('no-provider')
    expect(empty).not.toContain('/auth/google')
    expect(empty).not.toContain('/auth/apple')
    expect(empty).not.toContain('/auth/facebook')

    const spaces = await open({ google: { clientId: '   ', exchange } }, false)
    expect(spaces).toContain('no-provider')
    expect(spaces).not.toContain('Continue with Google')

    const googleOnly = await open({ google: { clientId: 'google-client', exchange } }, false)
    expect(googleOnly).toContain('Continue with Google')
    expect(googleOnly).not.toContain('Continue with Apple')
    expect(googleOnly).not.toContain('Continue with Facebook')
    expect(googleOnly).not.toContain('no-provider')

    const testOnly = await open({}, true)
    expect(testOnly).toContain('<button type="submit">Sign in</button>')
    expect(testOnly).toContain('/test-login?')
    expect(testOnly).not.toContain('no-provider')
  } finally {
    await sessions.remove()
  }
})
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run packages/server/test/connect.test.ts -t "tells the person how to sign in|warns no-provider"`

Expected: FAIL. The current page has neither the sentence nor `no-provider`.

- [ ] **Step 3: Render the page**

Add `destinationName` to the existing import from `./connect.js`.

Replace `providersPage` in `packages/server/src/main.ts` with:

```ts
const ACCOUNT_STYLE =
  '.accounts{display:flex;flex-direction:column;gap:12px;max-width:320px}' +
  '.accounts a{display:flex;align-items:center;box-sizing:border-box;width:320px;height:40px;padding:0 12px;gap:12px;border:1px solid #747775;border-radius:4px;background:#fff;color:#1f1f1f;font:14px/20px sans-serif;text-decoration:none}' +
  '.accounts img{width:20px;height:20px;object-fit:contain;flex:none}'

function providersPage(ctx: Ctx, query: ConnectQuery): string {
  const links = PROVIDERS.flatMap((provider) => {
    if (!configured(ctx, provider)) return []
    return [{ href: authPath(provider, query), provider, label: `Continue with ${NAMES[provider]}` }]
  })
  const buttons = links
    .map((link) => {
      const href = escapeHtml(link.href)
      const label = escapeHtml(link.label)
      return `<a class="account" href="${href}"><img src="/marks/${link.provider}.svg" alt="" width="20" height="20">${label}</a>`
    })
    .join('')
  const test = ctx.testLogin ? testLoginForm(query) : ''
  const body =
    links.length === 0 && !ctx.testLogin
      ? '<h1>Sign in</h1><p>Sign-in is not set up.</p><p>no-provider</p>'
      : links.length === 0
        ? `<h1>Sign in</h1>${test}`
        : `<h1>Sign in</h1><p>To continue to ${escapeHtml(destinationName(query.audience, query.site))}, choose an account. You sign in on that site, then come back here.</p><div class="accounts">${buttons}</div>${test}`
  return `<!doctype html><html lang="en"><meta charset="utf-8"><title>Sign in</title><style>${ACCOUNT_STYLE}</style>${body}</html>`
}
```

`configured` already treats a blank client id as absent. `escapeHtml` already escapes `&`, `<`, `>`, `"`, and `'`. `testLoginForm` stays as it is.

Confirm `docs/admin.md` has a Warnings table whose code is `no-provider` and whose action names `SIGNET_GOOGLE_CLIENT_ID`, `SIGNET_APPLE_CLIENT_ID`, and `SIGNET_FACEBOOK_CLIENT_ID`. If that section is already present, do not edit it. If it is missing, add this section after the sentence that begins `A generated file writes the secrets`:

```md
## Warnings

The connect page shows a warning code when nobody can choose an account because this process is not configured. The code is on the page. This table is the list.

| Code | When it appears | What to do |
| --- | --- | --- |
| `no-provider` | No provider client id is set, and `SIGNET_TEST` is not `1`. The page has no account button. | Set `SIGNET_GOOGLE_CLIENT_ID`, `SIGNET_APPLE_CLIENT_ID`, or `SIGNET_FACEBOOK_CLIENT_ID`. A client secret without its client id leaves this code in place. On the public host, deploy the secrets so the machine boots with the new values. |
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npx vitest run packages/server/test/connect.test.ts`

Expected: PASS, including `shows a test sign-in instead of a blank page when no provider is configured` and `shows configured providers and signs only the stub subject`.

Then run: `npm test`

Expected: PASS for the whole suite.

- [ ] **Step 5: Commit**

```powershell
[System.IO.File]::WriteAllText("$env:TEMP\signet-commit.txt", "Tell a person how to choose an account on the sign-in page.`n`nThe connect page names the returning host, offers equal Continue with buttons, and shows no-provider when no account can be chosen.`n", (New-Object System.Text.UTF8Encoding $false))
git add packages/server/src/main.ts packages/server/test/connect.test.ts docs/admin.md
git commit -F "$env:TEMP\signet-commit.txt"
Remove-Item "$env:TEMP\signet-commit.txt"
```

`docs/admin.md` is included only if Step 3 had to add the Warnings section. If it was already committed, leave it out of `git add`.
