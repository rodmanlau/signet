# Sign out and switch account Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a site send the browser to Signet to sign out or to switch accounts, each on its own page, and let `@agenticage/client` open both.

**Architecture:** `GET /sign-out` shows one sentence and a POST button. The POST ends the single browser session and redirects with `#signet-identity=signed-out`. `GET /switch` shows the same sentence and the existing provider buttons. Google's switch link sends `prompt=select_account`. A finished sign-in replaces the previous session in the same write. The reference client listens on the audience, as `--human` already does, and prints the new URL.

**Tech Stack:** Node 22, TypeScript, `tsx`, Vitest, the existing `startLogin` test server. No new dependency.

**Spec:** `docs/superpowers/specs/2026-10-03-sign-out-and-switch-design.md`

## Global Constraints

- One Signet account per browser. A proof a site already holds stays valid until it expires. Signet does not notify other sites.
- `GET /connect`, `POST /logout` (empty `204`, no page), and `POST /agent-proof` stay as they are. Agents do not open the new pages.
- Query rules match `GET /connect`: `audience`, `return`, optional `site`. A return origin other than `audience` is `400` `rejected` with no `Location` header.
- Opening `GET /sign-out` or `GET /switch` does not set or clear the session cookie.
- Sign-out page title and heading are `Sign out`. The only sentence is `You are signed in as {label}.` The only control is a POST button `Sign out`. No "Stay signed in". No provider button.
- Switch page title and heading are `Switch account`. With a button or the test form, the only sentence is `You are signed in as {label}.` Buttons are `Continue with Google`, `Continue with Apple`, `Continue with Facebook`, configured ones only, same marks and order as sign-in. The Google link carries `prompt=select_account`. Apple and Facebook links do not carry `prompt`.
- With no session, `GET /switch` is the existing sign-in page. With no provider and test sign-in off, the switch page also shows `Sign-in is not set up.` and `no-provider`. A page with a button or the test form does not contain `no-provider`.
- Escape `&`, `<`, `>`, `"`, and `'` in the label and in every attribute.
- `GET /auth/google` forwards `prompt=select_account` only when the query value is exactly `select_account`. Any other value is ignored. Apple and Facebook ignore `prompt`. The sign-in page's Google link does not send `prompt`.
- A finished sign-in, provider callback or test sign-in, drops the previous session in the same session-file write. A provider failure leaves the previous session able to obtain a proof.
- Sign-out redirect is `303`, body text `signed-out`, fragment `#signet-identity=signed-out` (replacing any fragment already on the return URL). It clears the session cookie and the OAuth cookie the same way `POST /logout` does. If saving the session file fails, put the account back and do not redirect.
- There is no `#signet-identity=cancelled` fragment.
- Client usage is four lines, in the order `--agent`, `--human`, `--sign-out`, `--switch`. `--sign-out` takes origin and audience. `--switch` takes origin, audience, and the public-key file. The client does not print the agent secret or the proof bytes.
- The shell is PowerShell: do not use `&&`. Write commit messages as one sentence, UTF-8 no BOM, with `git commit -F`.

## Review Focus

- A session label `A&B <ada>` is shown as text on both pages. The sign-out task and the switch task each assert the escaped sentence.
- `POST /sign-out` with a return origin that is not the audience is `400`, has no `Location`, and the same session still obtains a proof from `GET /connect`. The sign-out task asserts this.
- `prompt=login` is not copied to Google, and `prompt=select_account` is not copied to Apple. The switch task asserts both authorize URLs.
- A provider failure while a session cookie is present redirects with `#signet-identity=failed`, and `GET /connect` with that cookie still returns a proof for the old label. The replacement task asserts this.
- `--sign-out` reports a posted proof as `Redirect. proof` and the log does not contain the proof token. The client task asserts this.

---

### Task 1: Sign out

**Files:**
- Modify: `packages/server/src/main.ts` (route in `handle`, new `acceptedQuery`, `signOutLocation`, `signOutPage`, `handleSignOut`)
- Modify: `docs/admin.md` (routes table)
- Test: `packages/server/test/connect.test.ts`

**Interfaces:**
- Consumes: `connectQuery`, `decideConnect`, `escapeHtml`, `queryPath`, `readSession`, `persist`, `clearCookie`, `sendHtml`, `sendRedirect`, `sendText`, `ConnectQuery`.
- Produces: `acceptedQuery(ctx: Ctx, url: URL): ConnectQuery | null`. Later tasks call this for `GET /switch`. It returns the query when `connectQuery` accepts it and `decideConnect` with `session: null` returns `providers`. Otherwise `null`.

- [ ] **Step 1: Write the failing test**

Add this test inside `describe('login origin')` in `packages/server/test/connect.test.ts`. `startLogin`, `generateKeyPair`, `tempSessions`, `setCookie`, and `cookieValue` are already in that file.

```ts
it('signs the browser out from the sign-out page', async () => {
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
    testLogin: true,
    providers: {},
    sessionsFile: sessions.file,
  })
  try {
    const minted = await fetch(new URL('/test-login', server.url), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ provider: 'google', subject: 'ada', label: 'A&B <ada>' }),
    })
    const session = cookieValue(setCookie(minted, 'valar_session'))
    const signOut = new URL('/sign-out', server.url)
    signOut.searchParams.set('audience', 'https://friends.example')
    signOut.searchParams.set('return', 'https://friends.example/room?x=1#keep')
    const page = await fetch(signOut, { headers: { cookie: `valar_session=${session}` } })
    expect(page.status).toBe(200)
    expect(page.headers.getSetCookie().some((line) => line.startsWith('valar_session='))).toBe(false)
    const html = await page.text()
    expect(html).toContain('<title>Sign out</title>')
    expect(html).toContain('<h1>Sign out</h1>')
    expect(html).toContain('You are signed in as A&amp;B &lt;ada&gt;.')
    expect(html).toContain('<button type="submit">Sign out</button>')
    expect(html).toContain('method="post"')
    expect(html).toContain('action="/sign-out?')
    expect(html).toContain('audience=https%3A%2F%2Ffriends.example')
    expect(html).not.toContain('Continue with Google')
    expect(html).not.toContain('Stay signed in')
    expect(html).not.toContain('signet-identity=cancelled')

    const connect = new URL('/connect', server.url)
    connect.searchParams.set('audience', 'https://friends.example')
    connect.searchParams.set('return', 'https://friends.example/room')
    const still = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${session}` } })
    expect(still.status).toBe(200)
    expect(await still.text()).toContain('Signed in as A&amp;B &lt;ada&gt;.')

    const evil = new URL('/sign-out', server.url)
    evil.searchParams.set('audience', 'https://friends.example')
    evil.searchParams.set('return', 'https://evil.example/room')
    const rejected = await fetch(evil, {
      method: 'POST',
      redirect: 'manual',
      headers: { cookie: `valar_session=${session}` },
    })
    expect(rejected.status).toBe(400)
    expect(rejected.headers.get('location')).toBeNull()
    const kept = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${session}` } })
    expect(await kept.text()).toContain('Signed in as A&amp;B &lt;ada&gt;.')

    const other = await fetch(signOut, { method: 'PUT', redirect: 'manual' })
    expect(other.status).toBe(405)
    expect(other.headers.get('allow')).toBe('GET, POST')

    const posted = await fetch(signOut, {
      method: 'POST',
      redirect: 'manual',
      headers: { cookie: `valar_session=${session}` },
    })
    expect(posted.status).toBe(303)
    expect(await posted.text()).toBe('signed-out')
    const back = new URL(posted.headers.get('location') ?? '')
    expect(back.origin).toBe('https://friends.example')
    expect(back.pathname).toBe('/room')
    expect(back.search).toBe('?x=1')
    expect(back.hash).toBe('#signet-identity=signed-out')
    const cleared = setCookie(posted, 'valar_session')
    expect(cleared).toContain('Max-Age=0')
    expect(setCookie(posted, 'valar_oauth')).toContain('Max-Age=0')

    const after = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${session}` } })
    expect(await after.text()).toContain('<h1>Sign in</h1>')

    const gone = await fetch(signOut, { redirect: 'manual' })
    expect(gone.status).toBe(303)
    expect(new URL(gone.headers.get('location') ?? '').hash).toBe('#signet-identity=signed-out')
    const gonePost = await fetch(signOut, { method: 'POST', redirect: 'manual' })
    expect(gonePost.status).toBe(303)
    expect(new URL(gonePost.headers.get('location') ?? '').hash).toBe('#signet-identity=signed-out')
  } finally {
    await server.close()
    await sessions.remove()
  }
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run packages/server/test/connect.test.ts`

Expected: FAIL. The new test does not receive the sign-out page. `404` or a missing heading is enough.

- [ ] **Step 3: Implement sign-out**

In `handle`, before the `/logout` line:

```ts
if (path === '/sign-out') return await handleSignOut(req, res, ctx, url)
```

Add these functions next to `handleLogout`:

```ts
function acceptedQuery(ctx: Ctx, url: URL): ConnectQuery | null {
  const query = connectQuery(url)
  if (!query) return null
  const decision = decideConnect({
    session: null,
    audience: query.audience,
    returnUrl: query.returnUrl,
    now: ctx.now(),
    issuer: ctx.issuer,
    keyId: ctx.keyId,
    privateKey: ctx.privateKey,
    derivationKey: ctx.derivationKey,
  })
  if (decision.type === 'reject') return null
  return query
}

function signOutLocation(query: ConnectQuery): string {
  const url = new URL(query.returnUrl)
  url.hash = 'signet-identity=signed-out'
  return url.href
}

function signOutPage(label: string, query: ConnectQuery): string {
  const action = escapeHtml(queryPath('/sign-out', query))
  return (
    '<!doctype html><html lang="en"><meta charset="utf-8"><title>Sign out</title><h1>Sign out</h1>' +
    `<p>You are signed in as ${escapeHtml(label)}.</p>` +
    `<form method="post" action="${action}"><button type="submit">Sign out</button></form></html>`
  )
}

async function handleSignOut(req: IncomingMessage, res: ServerResponse, ctx: Ctx, url: URL): Promise<void> {
  if (req.method !== 'GET' && req.method !== 'POST') {
    return sendText(res, 405, 'method not allowed', { allow: 'GET, POST' })
  }
  const query = acceptedQuery(ctx, url)
  if (!query) return sendText(res, 400, 'rejected')
  const stored = readSession(ctx, req.headers.cookie)
  if (req.method === 'GET' && stored) {
    sendHtml(res, 200, signOutPage(stored.label, query))
    return
  }
  if (req.method === 'POST' && stored) {
    ctx.sessions.delete(stored.id)
    try {
      await persist(ctx)
    } catch (error) {
      ctx.sessions.set(stored.id, { provider: stored.provider, subject: stored.subject, label: stored.label })
      throw error
    }
  }
  const location = signOutLocation(query)
  if (/[\r\n]/.test(location)) return sendText(res, 400, 'rejected')
  sendRedirect(res, 303, location, 'signed-out', [
    clearCookie(SESSION_COOKIE, sessionFlags(ctx.issuer)),
    clearCookie(OAUTH_COOKIE, OAUTH_FLAGS),
  ])
}
```

In `docs/admin.md`, add this row after the `GET /connect` row:

```markdown
| `GET /sign-out?audience=<origin>&return=<url>` | Optional `site`. With a session, the page says `You are signed in as {label}.` and its button posts to this URL. The POST ends the browser session and redirects to `return` with `#signet-identity=signed-out`. With no session, the GET redirects there. The return URL's origin must equal `audience`. |
```

Leave the `POST /logout` row as it is.

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run packages/server/test/connect.test.ts`

Expected: PASS, including the existing login tests.

- [ ] **Step 5: Commit**

```powershell
node -e "require('fs').writeFileSync(process.env.TEMP + '/signet-msg.txt', 'Add the sign-out page.\n')"
git add packages/server/src/main.ts packages/server/test/connect.test.ts docs/admin.md
git commit -F "$env:TEMP/signet-msg.txt"
```

---

### Task 2: Switch account page

**Files:**
- Modify: `packages/server/src/main.ts` (`handle`, `authPath`, `authorizeLocation`, `handleAuth`, `providersPage`, new `switchPage` and `handleSwitch`)
- Modify: `docs/admin.md` (routes table)
- Test: `packages/server/test/connect.test.ts`

**Interfaces:**
- Consumes: `acceptedQuery` from Task 1. `providersPage`, `authPath`, `testLoginForm`, `NAMES`, `PROVIDERS`, `ACCOUNT_STYLE`, `configured`.
- Produces: `GET /switch` HTML. `authPath(provider, query, prompt?: 'select_account')` appends `prompt=select_account` only when the third argument is that value. `authorizeLocation(..., prompt?: 'select_account')` sets Google's `prompt` only for that value.

- [ ] **Step 1: Write the failing test**

Add this test inside `describe('login origin')`.

```ts
it('offers the configured accounts on the switch page', async () => {
  const { secretKey, publicKey } = await generateKeyPair()
  const exchange = async () => ({ subject: 'ada', label: 'Ada' })
  const sessionsOn = await tempSessions()
  const on = await startLogin({
    port: 0,
    issuer: 'https://login.example',
    keyId: 'k1',
    privateKey: secretKey,
    publicKey,
    derivationKey: new TextEncoder().encode('0123456789abcdef0123456789abcdef'),
    now: () => 1_700_000_000,
    testLogin: true,
    sessionsFile: sessionsOn.file,
    providers: {
      google: { clientId: 'google-client', authorizeUrl: 'https://provider.test/auth', exchange },
      apple: { clientId: 'apple-client', authorizeUrl: 'https://apple.test/auth', exchange },
      facebook: { clientId: 'facebook-client', authorizeUrl: 'https://facebook.test/auth', exchange },
    },
  })
  try {
    const minted = await fetch(new URL('/test-login', on.url), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ provider: 'google', subject: 'ada', label: 'A&B <ada>' }),
    })
    const session = cookieValue(setCookie(minted, 'valar_session'))
    const cookie = { cookie: `valar_session=${session}` }
    const switchUrl = new URL('/switch', on.url)
    switchUrl.searchParams.set('audience', 'https://friends.example')
    switchUrl.searchParams.set('return', 'https://friends.example/room')
    const page = await fetch(switchUrl, { headers: cookie })
    expect(page.status).toBe(200)
    expect(page.headers.getSetCookie().some((line) => line.startsWith('valar_session='))).toBe(false)
    const html = await page.text()
    expect(html).toContain('<title>Switch account</title>')
    expect(html).toContain('<h1>Switch account</h1>')
    expect(html).toContain('You are signed in as A&amp;B &lt;ada&gt;.')
    expect(html).toContain('Continue with Google')
    expect(html).toContain('Continue with Apple')
    expect(html).toContain('Continue with Facebook')
    expect(html).not.toContain('>Sign out<')
    expect(html).not.toContain('no-provider')
    const googleHref = html.match(/href="([^"]*\/auth\/google[^"]*)"/)?.[1] ?? ''
    const appleHref = html.match(/href="([^"]*\/auth\/apple[^"]*)"/)?.[1] ?? ''
    const facebookHref = html.match(/href="([^"]*\/auth\/facebook[^"]*)"/)?.[1] ?? ''
    expect(new URL(googleHref, on.url).searchParams.get('prompt')).toBe('select_account')
    expect(new URL(appleHref, on.url).searchParams.get('prompt')).toBeNull()
    expect(new URL(facebookHref, on.url).searchParams.get('prompt')).toBeNull()
    expect(html.indexOf('Continue with Google')).toBeLessThan(html.indexOf('Continue with Apple'))
    expect(html.indexOf('Continue with Apple')).toBeLessThan(html.indexOf('Continue with Facebook'))

    const bare = await fetch(switchUrl)
    const bareHtml = await bare.text()
    expect(bareHtml).toContain('<title>Sign in</title>')
    expect(bareHtml).toContain('choose an account')
    expect(bareHtml).not.toContain('You are signed in as')
    expect(bareHtml).not.toContain('prompt=select_account')

    const posted = await fetch(switchUrl, { method: 'POST' })
    expect(posted.status).toBe(405)
    expect(posted.headers.get('allow')).toBe('GET')

    const google = new URL('/auth/google', on.url)
    google.searchParams.set('audience', 'https://friends.example')
    google.searchParams.set('return', 'https://friends.example/room')
    google.searchParams.set('prompt', 'select_account')
    const began = await fetch(google, { redirect: 'manual' })
    expect(new URL(began.headers.get('location') ?? '').searchParams.get('prompt')).toBe('select_account')

    const plain = new URL('/auth/google', on.url)
    plain.searchParams.set('audience', 'https://friends.example')
    plain.searchParams.set('return', 'https://friends.example/room')
    const plainBegan = await fetch(plain, { redirect: 'manual' })
    expect(new URL(plainBegan.headers.get('location') ?? '').searchParams.get('prompt')).toBeNull()

    const loginPrompt = new URL(google)
    loginPrompt.searchParams.set('prompt', 'login')
    const ignored = await fetch(loginPrompt, { redirect: 'manual' })
    expect(new URL(ignored.headers.get('location') ?? '').searchParams.get('prompt')).toBeNull()

    const apple = new URL('/auth/apple', on.url)
    apple.searchParams.set('audience', 'https://friends.example')
    apple.searchParams.set('return', 'https://friends.example/room')
    apple.searchParams.set('prompt', 'select_account')
    const appleBegan = await fetch(apple, { redirect: 'manual' })
    expect(new URL(appleBegan.headers.get('location') ?? '').searchParams.get('prompt')).toBeNull()
  } finally {
    await on.close()
    await sessionsOn.remove()
  }

  const quietSessions = await tempSessions()
  const quietId = 'quiet-session-id1'
  await writeFile(
    quietSessions.file,
    JSON.stringify({ [quietId]: { provider: 'google', subject: 'ada', label: 'Ada' } }),
  )
  const quiet = await startLogin({
    port: 0,
    issuer: 'https://login.example',
    keyId: 'k1',
    privateKey: secretKey,
    publicKey,
    derivationKey: new TextEncoder().encode('0123456789abcdef0123456789abcdef'),
    now: () => 1_700_000_000,
    testLogin: false,
    providers: {},
    sessionsFile: quietSessions.file,
  })
  const formSessions = await tempSessions()
  const form = await startLogin({
    port: 0,
    issuer: 'https://login.example',
    keyId: 'k1',
    privateKey: secretKey,
    publicKey,
    derivationKey: new TextEncoder().encode('0123456789abcdef0123456789abcdef'),
    now: () => 1_700_000_000,
    testLogin: true,
    providers: {},
    sessionsFile: formSessions.file,
  })
  try {
    const quietPage = new URL('/switch', quiet.url)
    quietPage.searchParams.set('audience', 'https://friends.example')
    quietPage.searchParams.set('return', 'https://friends.example/room')
    const warned = await fetch(quietPage, { headers: { cookie: `valar_session=${quietId}` } })
    const warnedHtml = await warned.text()
    expect(warnedHtml).toContain('You are signed in as Ada.')
    expect(warnedHtml).toContain('Sign-in is not set up.')
    expect(warnedHtml).toContain('no-provider')
    expect(warnedHtml).not.toContain('/auth/google')

    const minted = await fetch(new URL('/test-login', form.url), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ provider: 'google', subject: 'ada', label: 'Ada' }),
    })
    const formCookie = cookieValue(setCookie(minted, 'valar_session'))
    const formPage = new URL('/switch', form.url)
    formPage.searchParams.set('audience', 'https://friends.example')
    formPage.searchParams.set('return', 'https://friends.example/room')
    const formed = await fetch(formPage, { headers: { cookie: `valar_session=${formCookie}` } })
    const formedHtml = await formed.text()
    expect(formedHtml).toContain('You are signed in as Ada.')
    expect(formedHtml).toContain('<button type="submit">Sign in</button>')
    expect(formedHtml).not.toContain('no-provider')
  } finally {
    await quiet.close()
    await form.close()
    await quietSessions.remove()
    await formSessions.remove()
  }
})
```

`writeFile` is already imported in `connect.test.ts`. The quiet session id is 17 characters, which matches the session id pattern.

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run packages/server/test/connect.test.ts`

Expected: FAIL on the switch page, before any authorize assertion.

- [ ] **Step 3: Implement the switch page**

In `handle`, next to the sign-out route:

```ts
if (path === '/switch') return await handleSwitch(req, res, ctx, url)
```

Change `authPath` to:

```ts
function authPath(provider: ProviderName, query: ConnectQuery, prompt?: 'select_account'): string {
  const path = queryPath(`/auth/${provider}`, query)
  if (prompt === undefined) return path
  const params = new URLSearchParams(path.slice(path.indexOf('?') + 1))
  params.set('prompt', prompt)
  return `${path.slice(0, path.indexOf('?'))}?${params.toString()}`
}
```

Add `prompt?: 'select_account'` as the last parameter of `authorizeLocation`. After the Google `scope` line:

```ts
if (provider === 'google' && prompt === 'select_account') url.searchParams.set('prompt', 'select_account')
```

In `handleAuth`, after the query is accepted:

```ts
const prompt = url.searchParams.get('prompt') === 'select_account' ? 'select_account' : undefined
const location = authorizeLocation(
  provider,
  config,
  `${ctx.issuer}/auth/${provider}/callback`,
  state,
  provider === 'google' ? prompt : undefined,
)
```

Replace the existing `authorizeLocation(...)` call with that call. Do not store `prompt` in `PendingLogin`.

Add `switchPage` and `handleSwitch` beside `providersPage`. Build the links the same way `providersPage` does, and pass `'select_account'` to `authPath` only for Google.

```ts
function switchPage(ctx: Ctx, query: ConnectQuery, label: string): string {
  const links = PROVIDERS.flatMap((provider) => {
    if (!configured(ctx, provider)) return []
    return [{
      href: authPath(provider, query, provider === 'google' ? 'select_account' : undefined),
      provider,
      label: `Continue with ${NAMES[provider]}`,
    }]
  })
  const buttons = links
    .map((link) => {
      const href = escapeHtml(link.href)
      const text = escapeHtml(link.label)
      const mark = link.provider === 'apple' ? '40' : '20'
      return `<a class="account" href="${href}"><img class="${link.provider}" src="/marks/${link.provider}.svg" alt="" width="${mark}" height="${mark}">${text}</a>`
    })
    .join('')
  const test = ctx.testLogin ? testLoginForm(query) : ''
  const sentence = `<p>You are signed in as ${escapeHtml(label)}.</p>`
  const body =
    links.length === 0 && !ctx.testLogin
      ? `<h1>Switch account</h1>${sentence}<p>Sign-in is not set up.</p><p>no-provider</p>`
      : links.length === 0
        ? `<h1>Switch account</h1>${sentence}${test}`
        : `<h1>Switch account</h1>${sentence}<div class="accounts">${buttons}</div>${test}`
  return `<!doctype html><html lang="en"><meta charset="utf-8"><title>Switch account</title><style>${ACCOUNT_STYLE}</style>${body}</html>`
}

async function handleSwitch(req: IncomingMessage, res: ServerResponse, ctx: Ctx, url: URL): Promise<void> {
  if (req.method !== 'GET') return sendText(res, 405, 'method not allowed', { allow: 'GET' })
  const query = acceptedQuery(ctx, url)
  if (!query) return sendText(res, 400, 'rejected')
  const stored = readSession(ctx, req.headers.cookie)
  if (!stored) {
    sendHtml(res, 200, providersPage(ctx, query))
    return
  }
  sendHtml(res, 200, switchPage(ctx, query, stored.label))
}
```

In `docs/admin.md`, add this row after the sign-out row:

```markdown
| `GET /switch?audience=<origin>&return=<url>` | Optional `site`. With a session, the page says `You are signed in as {label}.` and offers the configured account buttons. The Google button asks Google to show its account chooser. With no session, the response is the sign-in page. A finished sign-in replaces the browser account and returns a proof in `#signet-proof=`. A failed sign-in redirects with `#signet-identity=failed` and leaves the account in place. |
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run packages/server/test/connect.test.ts`

Expected: PASS. The existing sign-in page test still finds no `prompt` on its Google link.

- [ ] **Step 5: Commit**

```powershell
node -e "require('fs').writeFileSync(process.env.TEMP + '/signet-msg.txt', 'Add the switch account page.\n')"
git add packages/server/src/main.ts packages/server/test/connect.test.ts docs/admin.md
git commit -F "$env:TEMP/signet-msg.txt"
```

---

### Task 3: Replace the previous account

**Files:**
- Modify: `packages/server/src/main.ts` (`issueSession`, `handleCallback`, `handleTestLogin`)
- Test: `packages/server/test/connect.test.ts`

**Interfaces:**
- Consumes: `issueSession(ctx, session)` today. `readSession`. The callback and test-login paths that already call `issueSession`.
- Produces: `issueSession(ctx: Ctx, session: LoginSession, previousId?: string): Promise<string>`. When `previousId` is set, that id is removed in the same `persist` as the new id. On `persist` failure, the new id is removed and the previous record is put back.

- [ ] **Step 1: Write the failing test**

Add this test inside `describe('login origin')`. `readFile` is already imported.

```ts
it('replaces the browser account when a new sign-in finishes', async () => {
  const { secretKey, publicKey } = await generateKeyPair()
  const derivationKey = new TextEncoder().encode('0123456789abcdef0123456789abcdef')
  let subject = 'ada'
  let label = 'Ada'
  const sessions = await tempSessions()
  const server = await startLogin({
    port: 0,
    issuer: 'https://login.example',
    keyId: 'k1',
    privateKey: secretKey,
    publicKey,
    derivationKey,
    now: () => 1_700_000_000,
    testLogin: true,
    sessionsFile: sessions.file,
    providers: {
      google: {
        clientId: 'google-client',
        authorizeUrl: 'https://provider.test/auth',
        exchange: async (code) => {
          if (code === 'bad') throw new Error('provider down')
          return { subject, label }
        },
      },
    },
  })
  const connect = new URL('/connect', server.url)
  connect.searchParams.set('audience', 'https://friends.example')
  connect.searchParams.set('return', 'https://friends.example/room')
  const finish = async (code: string, session?: string) => {
    const start = new URL('/auth/google', server.url)
    start.searchParams.set('audience', 'https://friends.example')
    start.searchParams.set('return', 'https://friends.example/room')
    const began = await fetch(start, { redirect: 'manual' })
    const state = new URL(began.headers.get('location') ?? '').searchParams.get('state') ?? ''
    const nonce = cookieValue(setCookie(began, 'valar_oauth'))
    const callback = new URL('/auth/google/callback', server.url)
    callback.searchParams.set('code', code)
    callback.searchParams.set('state', state)
    const headers: Record<string, string> = { cookie: `valar_oauth=${nonce}` }
    if (session !== undefined) headers.cookie = `valar_oauth=${nonce}; valar_session=${session}`
    return fetch(callback, { redirect: 'manual', headers })
  }
  try {
    const first = await finish('ok')
    expect(first.status).toBe(200)
    const firstId = cookieValue(setCookie(first, 'valar_session'))

    subject = 'bea'
    label = 'Bea'
    const failed = await finish('bad', firstId)
    expect(failed.status).toBe(303)
    expect(new URL(failed.headers.get('location') ?? '').hash).toBe('#signet-identity=failed')
    const still = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${firstId}` } })
    expect(await still.text()).toContain('Signed in as Ada.')

    const second = await finish('ok', firstId)
    expect(second.status).toBe(200)
    expect(await second.text()).toContain('Signed in as Bea. Taking you back to friends.example.')
    const secondId = cookieValue(setCookie(second, 'valar_session'))
    expect(secondId).not.toBe(firstId)
    const stored = JSON.parse(await readFile(sessions.file, 'utf8')) as Record<string, { label: string }>
    expect(Object.keys(stored)).toEqual([secondId])
    expect(stored[secondId]?.label).toBe('Bea')
    const old = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${firstId}` } })
    expect(await old.text()).toContain('<h1>Sign in</h1>')
    const newer = await fetch(connect, { redirect: 'manual', headers: { cookie: `valar_session=${secondId}` } })
    expect(await newer.text()).toContain('Signed in as Bea.')

    subject = 'bea'
    label = 'Bea'
    const same = await finish('ok', secondId)
    const sameId = cookieValue(setCookie(same, 'valar_session'))
    expect(sameId).not.toBe(secondId)
    const afterSame = JSON.parse(await readFile(sessions.file, 'utf8')) as Record<string, { subject: string }>
    expect(Object.keys(afterSame)).toEqual([sameId])
    expect(afterSame[sameId]?.subject).toBe('bea')
  } finally {
    await server.close()
    await sessions.remove()
  }
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run packages/server/test/connect.test.ts`

Expected: FAIL. After the second sign-in the session file still contains the first id, or `GET /connect` with the first cookie still shows Ada.

- [ ] **Step 3: Drop the previous session when the new one is saved**

Change `issueSession` to:

```ts
async function issueSession(ctx: Ctx, session: LoginSession, previousId?: string): Promise<string> {
  const id = randomBytes(16).toString('base64url')
  const previous = previousId === undefined ? undefined : ctx.sessions.get(previousId)
  if (previousId !== undefined) ctx.sessions.delete(previousId)
  ctx.sessions.set(id, session)
  try {
    await persist(ctx)
  } catch (error) {
    ctx.sessions.delete(id)
    if (previous !== undefined && previousId !== undefined) ctx.sessions.set(previousId, previous)
    throw error
  }
  return sessionCookie(id, ctx.issuer)
}
```

In `handleCallback`, before `issueSession`, `const previous = readSession(ctx, req.headers.cookie)`. Pass `previous?.id` as the third argument.

In `handleTestLogin`, read the current session the same way and pass its id to both `issueSession` calls. Read it only after the return URL has been accepted, so a rejected test login does not drop the account. For the `204` path, which has no return URL, pass the id as well.

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run packages/server/test/connect.test.ts`

Expected: PASS. The older test that repeats `GET /connect` with the same cookie still sees that same cookie value. That path does not call `issueSession`.

- [ ] **Step 5: Commit**

```powershell
node -e "require('fs').writeFileSync(process.env.TEMP + '/signet-msg.txt', 'Replace the previous account when sign-in finishes.\n')"
git add packages/server/src/main.ts packages/server/test/connect.test.ts
git commit -F "$env:TEMP/signet-msg.txt"
```

---

### Task 4: Client commands

**Files:**
- Modify: `packages/client/src/run.ts`
- Modify: `packages/client/test/client.test.ts`
- Modify: `docs/develop.md`
- Modify: `docs/admin.md` (the closing client sentence)

**Interfaces:**
- Consumes: `listenForProof`, `proofFromFragment`, `finishProof`, `loopbackAudience`, `isOrigin`, `Heard`.
- Produces: `--sign-out` and `--switch` on `runSignetClient`. `listenForProof` gains a path argument, `'/connect' | '/sign-out' | '/switch'`, and writes `4. Open {origin}{path}?audience=…&return=…`.

- [ ] **Step 1: Write the failing tests**

Replace the `USAGE` array in `packages/client/test/client.test.ts` with:

```ts
const USAGE = [
  'npm start -w @agenticage/client -- --agent <signet-origin> <audience> <agent-key-file> <public-key-file>',
  'npm start -w @agenticage/client -- --human <signet-origin> <audience> <public-key-file>',
  'npm start -w @agenticage/client -- --sign-out <signet-origin> <audience>',
  'npm start -w @agenticage/client -- --switch <signet-origin> <audience> <public-key-file>',
]
```

Extend the argv list in `prints both commands when the switch is missing or repeated` so it also includes `['--sign-out', '--switch']` and `['--sign-out', 'http://127.0.0.1:8787']`. Rename that test to `prints every command when the mode is missing or repeated`.

Add:

```ts
it('prints the sign-out URL and stops after the signed-out fragment', async () => {
  const audience = `http://127.0.0.1:${await freePort()}`
  const signet = 'http://127.0.0.1:8787'
  const lines: string[] = []
  const pending = runSignetClient(['--sign-out', signet, audience], (line) => lines.push(line))
  try {
    await waitFor(lines, '4. Open')
    expect(lines[3]).toBe(
      `4. Open ${signet}/sign-out?audience=${encodeURIComponent(audience)}&return=${encodeURIComponent(`${audience}/`)}`,
    )
    const posted = await fetch(audience, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: '#signet-identity=signed-out',
    })
    expect(posted.status).toBe(204)
    expect(await pending).toBe(0)
    expect(lines[4]).toBe('5. Redirect. #signet-identity=signed-out')
    expect(lines).toHaveLength(5)
  } finally {
    await Promise.race([pending, new Promise((resolve) => setTimeout(resolve, 200))])
  }
})

it('reports a proof posted to sign-out without printing the token', async () => {
  const { secretKey, publicKey } = await generateKeyPair()
  const audience = `http://127.0.0.1:${await freePort()}`
  const signet = 'http://127.0.0.1:8787'
  const now = Math.floor(Date.now() / 1000)
  const proof = signProof(
    { keyId: 'k1', issuer: signet, identity: 'ab'.repeat(32), audience, issuedAt: now, expiresAt: now + 60 },
    secretKey,
  )
  const token = Buffer.from(proof).toString('base64url')
  const lines: string[] = []
  const pending = runSignetClient(['--sign-out', signet, audience], (line) => lines.push(line))
  try {
    await waitFor(lines, '4. Open')
    const posted = await fetch(audience, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: `#signet-proof=${token}`,
    })
    expect(posted.status).toBe(204)
    expect(await pending).toBe(1)
    expect(lines[4]).toBe('5. Redirect. proof')
    expect(lines.join('\n')).not.toContain(token)
    expect(lines.join('\n')).not.toContain(Buffer.from(publicKey).toString('base64'))
  } finally {
    await Promise.race([pending, new Promise((resolve) => setTimeout(resolve, 200))])
  }
})

it('prints the switch URL and checks the proof the way human sign-in does', async () => {
  const { secretKey, publicKey } = await generateKeyPair()
  const audience = `http://127.0.0.1:${await freePort()}`
  const signet = 'http://127.0.0.1:8787'
  const dir = await mkdtemp(join(tmpdir(), 'signet-client-'))
  const keyFile = join(dir, 'keys.json')
  await writeFile(keyFile, JSON.stringify([{ id: 'k1', publicKey: Buffer.from(publicKey).toString('base64') }]))
  const now = Math.floor(Date.now() / 1000)
  const identity = 'cd'.repeat(32)
  const proof = signProof(
    { keyId: 'k1', issuer: signet, identity, audience, issuedAt: now, expiresAt: now + 60 },
    secretKey,
  )
  const lines: string[] = []
  const pending = runSignetClient(['--switch', signet, audience, keyFile], (line) => lines.push(line))
  try {
    await waitFor(lines, '4. Open')
    expect(lines[3]).toBe(
      `4. Open ${signet}/switch?audience=${encodeURIComponent(audience)}&return=${encodeURIComponent(`${audience}/`)}`,
    )
    const token = Buffer.from(proof).toString('base64url')
    const posted = await fetch(audience, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: `#signet-proof=${token}`,
    })
    expect(posted.status).toBe(204)
    expect(await pending).toBe(0)
    expect(lines[4]).toBe(`5. Redirect. Proof bytes: ${proof.byteLength}`)
    expect(lines[7]).toBe(`8. Identity: ${identity}`)
    expect(lines.join('\n')).not.toContain(token)
  } finally {
    await Promise.race([pending, new Promise((resolve) => setTimeout(resolve, 200))])
    await rm(dir, { recursive: true, force: true })
  }
})
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run packages/client/test/client.test.ts`

Expected: FAIL. Usage does not include `--sign-out`, or `--sign-out` is printed as usage.

- [ ] **Step 3: Implement the commands**

In `packages/client/src/run.ts`, replace `USAGE` and the mode check at the start of `runSignetClient`:

```ts
const USAGE = [
  'npm start -w @agenticage/client -- --agent <signet-origin> <audience> <agent-key-file> <public-key-file>',
  'npm start -w @agenticage/client -- --human <signet-origin> <audience> <public-key-file>',
  'npm start -w @agenticage/client -- --sign-out <signet-origin> <audience>',
  'npm start -w @agenticage/client -- --switch <signet-origin> <audience> <public-key-file>',
]

const MODES = ['--agent', '--human', '--sign-out', '--switch'] as const

export async function runSignetClient(argv: string[], write: Write): Promise<number> {
  const chosen = MODES.filter((mode) => argv.includes(mode))
  if (chosen.length !== 1 || argv[0] !== chosen[0]) return writeUsage(write)
  const mode = chosen[0]
  if (mode === '--agent') {
    if (argv.length !== 5) return writeUsage(write)
    return runAgent(argv[1] ?? '', argv[2] ?? '', argv[3] ?? '', argv[4] ?? '', write)
  }
  if (mode === '--sign-out') {
    if (argv.length !== 3) return writeUsage(write)
    return runBrowser(argv[1] ?? '', argv[2] ?? '', '/sign-out', undefined, write)
  }
  if (argv.length !== 4) return writeUsage(write)
  const path = mode === '--human' ? '/connect' : '/switch'
  return runBrowser(argv[1] ?? '', argv[2] ?? '', path, argv[3] ?? '', write)
}
```

Replace `runHuman` and `listenForProof` with:

```ts
async function runBrowser(
  origin: string,
  audience: string,
  path: '/connect' | '/sign-out' | '/switch',
  publicKeyFile: string | undefined,
  write: Write,
): Promise<number> {
  if (!isOrigin(origin)) {
    write(`1. Signet origin: ${origin}. bad origin`)
    return 1
  }
  write(`1. Signet origin: ${origin}`)
  const url = loopbackAudience(audience)
  if (url === null) {
    write(`2. Audience: ${audience}. The proof would be returned to that origin.`)
    return 1
  }
  write(`2. Audience: ${audience}`)

  const heard = await listenForReturn(url, audience, origin, path, write)
  if (heard.kind === 'listen') {
    write(`3. Listening on ${audience}. ${heard.reason}`)
    return 1
  }
  if (publicKeyFile === undefined) {
    if (heard.kind === 'proof') {
      write('5. Redirect. proof')
      return 1
    }
    write(`5. Redirect. ${heard.reason}`)
    return heard.reason === '#signet-identity=signed-out' ? 0 : 1
  }
  if (heard.kind === 'redirect') {
    write(`5. Redirect. ${heard.reason}`)
    return 1
  }
  write(`5. Redirect. Proof bytes: ${heard.bytes.byteLength}`)
  return finishProof(heard.bytes, origin, audience, publicKeyFile, 6, write)
}

function listenForReturn(
  url: URL,
  audience: string,
  origin: string,
  path: '/connect' | '/sign-out' | '/switch',
  write: Write,
): Promise<Heard> {
  return new Promise((resolve) => {
    let settled = false
    let listening = false
    const finish = (heard: Heard) => {
      if (settled) return
      settled = true
      resolve(heard)
    }
    const server = createServer((req, res) => {
      if (req.method === 'GET') {
        sendPage(res)
        return
      }
      if (req.method !== 'POST') {
        res.writeHead(405, { allow: 'GET, POST' })
        res.end()
        return
      }
      void readLimited(req, 8192)
        .then((body) => {
          const heard = proofFromFragment(body)
          res.writeHead(204, { connection: 'close' })
          res.end(() => {
            server.close()
            finish(heard)
          })
        })
        .catch((error: unknown) => {
          const heard: Heard = { kind: 'redirect', reason: errorMessage(error) }
          if (res.headersSent) {
            server.close()
            finish(heard)
            return
          }
          res.writeHead(204, { connection: 'close' })
          res.end(() => {
            server.close()
            finish(heard)
          })
        })
    })
    server.on('error', (error) => {
      if (listening) return
      server.close()
      finish({ kind: 'listen', reason: errorMessage(error) })
    })
    server.listen(Number(url.port), url.hostname, () => {
      listening = true
      server.unref()
      if (process.env.VITEST !== 'true') server.ref()
      const params = new URLSearchParams()
      params.set('audience', audience)
      params.set('return', `${audience}/`)
      write(`3. Listening on ${audience}`)
      write(`4. Open ${origin}${path}?${params.toString()}`)
    })
  })
}
```

Keep `sendPage`, `proofFromFragment`, and `finishProof` as they are.

In `docs/develop.md`, after the paragraph `An agent does not open this page.`, add:

```markdown
## Sign out or switch

Send the person to one of these. The query is the same as `/connect`: `audience`, `return`, and an optional `site`. The return URL's origin must equal `audience`.

```text
GET /sign-out?audience=<origin>&return=<url>
GET /switch?audience=<origin>&return=<url>
```

`GET /sign-out` shows `You are signed in as {label}.` and a Sign out button. The button posts back to that URL, ends the browser session, and redirects to `return` with `#signet-identity=signed-out`. With no session, the GET redirects there. The browser Back button leaves the session in place.

`GET /switch` shows the same sentence and the configured account buttons. The Google button asks Google to show its account chooser. With no session, Signet shows the sign-in page. A finished sign-in replaces the browser account and returns a proof in `#signet-proof=`. A failed sign-in redirects with `#signet-identity=failed` and leaves the account in place.

A proof the site already holds stays valid until it expires. Signet does not tell other sites.
```

Replace the reference-client command block with the four usage lines from the spec. After the `--human` paragraph, add:

```markdown
`--sign-out` listens the same way and opens `/sign-out`. The log ends with `Redirect. #signet-identity=signed-out`. `--switch` listens the same way and opens `/switch`. A proof is checked the same way as `--human`.
```

In `docs/admin.md`, replace the closing client sentence with:

```markdown
`@agenticage/client` asks this process for one proof, or sends the browser to sign out or to switch accounts, and prints each step. It does not print the agent secret or the proof bytes. See the [developer guide](develop.md).
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npx vitest run packages/client/test/client.test.ts`

Expected: PASS, including the existing `--human` and `--agent` tests.

- [ ] **Step 5: Commit**

```powershell
node -e "require('fs').writeFileSync(process.env.TEMP + '/signet-msg.txt', 'Add sign-out and switch to the reference client.\n')"
git add packages/client/src/run.ts packages/client/test/client.test.ts docs/develop.md docs/admin.md
git commit -F "$env:TEMP/signet-msg.txt"
```

Then run `npm test` and expect the full suite to pass.
