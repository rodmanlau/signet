# Sign out and switch account

Date: 2026-10-03

Status: approved in conversation. Ready to implement.

## Purpose

A site that uses Signet can send the person's browser to Signet to sign out, or to switch accounts. The site already has both controls. Each control opens its own Signet page, and that page does only what the person chose.

Signet keeps one account for the browser. Signing out ends that account, so the next site that asks Signet has to sign in again. Switching replaces that account for every later request. A proof a site already holds stays valid until it expires. Signet does not tell other open sites. An open tab keeps working until its proof expires, at most 15 minutes.

This is for a person in a browser. An agent does not open these pages. `POST /agent-proof` is unchanged. `GET /connect` is unchanged. `POST /logout` still ends the session with an empty `204` and no page.

## The two requests

A site sends the person's browser with a GET. The query is the one `GET /connect` already accepts: `audience`, `return`, and an optional `site`. `audience` is the site's origin. The return URL's origin must equal that audience. A query `GET /connect` would reject is rejected here too, with `400` and the text `rejected`, and no `Location` header. Opening either GET leaves the account as it is.

| The person chose | The browser opens |
| --- | --- |
| Sign out | `GET /sign-out?audience=<origin>&return=<url>` |
| Switch account | `GET /switch?audience=<origin>&return=<url>` |

`site` is accepted on both. The sign-out page and the switch page do not show it. A later sign-in success page still uses it, by the rule the sign-in page already uses.

The site reads the result from the return URL's fragment.

| What happened | Fragment |
| --- | --- |
| Sign out finished, or the browser was already signed out | `#signet-identity=signed-out` |
| Switch finished with an account | `#signet-proof=` and the new proof |
| The provider returned a failure during switch | `#signet-identity=failed` |

There is no cancel fragment. The site opens Signet with a normal page navigation. The browser Back button restores the site and leaves the account as it is. Signet does not send a message for that.

A finished switch uses the existing return page: `Signed in as {label}. Taking you back to {destination}.` The proof is in `#signet-proof=`. Picking the same person still finishes this way. A failed switch leaves the previous account in place, and the fragment is `#signet-identity=failed`.

## Sign out

`GET /sign-out` and `POST /sign-out` are the only methods. Any other method is `405` with `Allow: GET, POST`.

With a session, `GET /sign-out` returns `200` and the page. It does not set or clear the session cookie.

The document title and the heading are `Sign out`.

The only sentence is:

`You are signed in as {label}.`

`{label}` is the session label, inserted as text. Characters that are special in HTML are escaped.

Under the sentence, one control: a POST form to this same `/sign-out` URL, carrying the same `audience`, `return`, and `site`. The button text is `Sign out`. The page has no other control and no other sentence.

The session cookie is `SameSite=Lax`. That POST carries the cookie when the form is on Signet.

A successful POST deletes the session and clears the session cookie and the OAuth cookie, the same cleanup `POST /logout` already does. The response is `303` to the return URL. That URL's fragment is `#signet-identity=signed-out`, replacing any fragment the return URL already had. The response body is the text `signed-out`. There is no intermediate page.

If saving the session file fails, the account is put back and the response is an error. The browser is not sent back as signed out.

With no account, `GET /sign-out` and `POST /sign-out` redirect the same way. The redirect clears the session cookie and the OAuth cookie. There is nothing to confirm.

## Switch account

`GET /switch` is the only method. Any other method is `405` with `Allow: GET`.

With no session, the response is the existing sign-in page, the same document `GET /connect` returns when there is no session.

With a session, the response is `200` and this page. It does not set or clear the session cookie.

The document title and the heading are `Switch account`.

When an account button or the test sign-in form is shown, the only sentence is:

`You are signed in as {label}.`

`{label}` is escaped the same way as on the sign-out page.

Under the sentence are the same provider buttons as the sign-in page, in the same order, and only for providers that are configured: `Continue with Google`, `Continue with Apple`, `Continue with Facebook`. Each button uses the same mark and the same link shape as sign-in. The Google link also carries `prompt=select_account`. The Apple and Facebook links do not carry `prompt`. With test sign-in on, the existing Sign in form follows the buttons, as it does on the sign-in page.

With no provider and test sign-in off, the sentence stays, and the page also shows `Sign-in is not set up.` and `no-provider`, and no account button. A page that shows an account button or the test sign-in form does not contain `no-provider`.

Choosing a button does not end the current account.

`GET /auth/google` adds `prompt=select_account` to Google's authorize URL when its own query contains `prompt=select_account`. Any other `prompt` value is ignored. Apple and Facebook ignore `prompt`. The sign-in page's Google link does not send `prompt`, so a normal sign-in does not ask Google for the account chooser.

When the new sign-in finishes, from a provider callback or from test sign-in, Signet saves that account and drops the previous one in the same write of the session file. The browser then has one account, the new one. The return page and the proof are the ones sign-in already uses. If saving the session file fails, the previous account is put back and the new one is not kept.

If the provider returns a failure, the fragment is `#signet-identity=failed` and the previous account is still there. `GET /connect` with that account still returns a proof.

## Reference client

`@agenticage/client` grows two commands beside `--human`. Both listen on the audience and print a URL to open. The audience must be `http://127.0.0.1:<port>` or `http://localhost:<port>`. Any other audience fails before the listen. The log says the proof would be returned to that origin. The return page is the one `--human` already serves. It posts the fragment.

```text
npm start -w @agenticage/client -- --sign-out <signet-origin> <audience>
npm start -w @agenticage/client -- --switch <signet-origin> <audience> <public-key-file>
```

`--sign-out` takes no public-key file. `--switch` takes the same public-key file as `--human`.

The usage text is these four lines, in this order:

```text
npm start -w @agenticage/client -- --agent <signet-origin> <audience> <agent-key-file> <public-key-file>
npm start -w @agenticage/client -- --human <signet-origin> <audience> <public-key-file>
npm start -w @agenticage/client -- --sign-out <signet-origin> <audience>
npm start -w @agenticage/client -- --switch <signet-origin> <audience> <public-key-file>
```

A missing mode, two of `--agent`, `--human`, `--sign-out`, and `--switch`, or the wrong number of arguments prints that usage and exits `1`.

`--sign-out` prints five lines and then exits:

1. `Signet origin: {origin}`, or `Signet origin: {origin}. bad origin` and exit `1`.
2. `Audience: {audience}`, or the existing failure sentence and exit `1`.
3. `Listening on {audience}`.
4. `Open {origin}/sign-out?audience=…&return=…`, with the return URL set to `{audience}/`.
5. `Redirect. #signet-identity=signed-out`, then exit `0`.

Any other fragment stops at step 5 with exit `1`. A proof is reported as `Redirect. proof`. The proof bytes stay out of the log. Back never reaches the return page, so the command keeps listening until the process stops.

`--switch` prints the same eight steps as `--human`. Step 4 opens `/switch` instead of `/connect`. A proof is checked and the identity is printed. `#signet-identity=failed` stops at step 5 with exit `1`.

`--agent` and `--human` keep their current steps. The client does not print the agent secret or the proof bytes.

## Guides

The developer guide lists the two commands with `--human`, and it describes `GET /sign-out` and `GET /switch` for a site that sends the person over.

The administrator guide lists `GET /sign-out`, `POST /sign-out`, and `GET /switch` beside the routes it already lists. `POST /logout` stays the no-page way to end the session.

## Tests

- With a session, `GET /sign-out` contains the heading `Sign out` and `You are signed in as {label}.`, and a POST button whose text is `Sign out`. A label that contains HTML-special characters is escaped. The page does not contain `Continue with Google` or `Stay signed in`. The response does not clear the session cookie.
- `POST /sign-out` with that session returns `303` to the return URL with `#signet-identity=signed-out`, clears the session cookie, and a later `GET /connect` with the old cookie shows the sign-in page.
- `GET /sign-out` and `POST /sign-out` with no session redirect the same way.
- A return origin that is not the audience is `400` on both `GET` and `POST`, with no `Location` header, and the session is still there.
- `GET /sign-out` does not end the session.
- With a session, `GET /switch` contains `Switch account` and `You are signed in as {label}.`, and the configured provider buttons. The Google link contains `prompt=select_account`. The Apple and Facebook links do not contain `prompt`. The page does not contain a `Sign out` button.
- With no session, `GET /switch` is the sign-in page.
- With no provider and test sign-in off, the switch page contains the sentence, `Sign-in is not set up.`, and `no-provider`, and no account link. With test sign-in on and no provider, the page contains the sentence and the Sign in form, and does not contain `no-provider`.
- `GET /auth/google` with `prompt=select_account` sends Google `prompt=select_account`. Without that parameter, and with any other `prompt` value, Google's authorize URL has no `prompt`. An Apple authorize URL has no `prompt` even when the query asks for one.
- A provider failure while a session exists redirects with `#signet-identity=failed` and leaves that session able to obtain a proof from `GET /connect`.
- A finished sign-in while a session exists stores only the new account. `GET /connect` with the new cookie returns a proof for the new account. `GET /connect` with the old cookie shows the sign-in page.
- The client prints the four usage lines when the mode is missing or repeated.
- `--sign-out` prints the `/sign-out` URL, exits `0` for `#signet-identity=signed-out`, and exits `1` for a proof fragment without printing the proof token.
- `--switch` prints the `/switch` URL and the same proof steps as `--human`.
