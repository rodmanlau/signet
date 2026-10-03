# Sign-in page

Date: 2026-10-02

Status: design for review.

## Purpose

A person who opens `GET /connect` without a session currently sees the provider names as bare links. The page tells them what to do, then offers each configured account as the same kind of button.

This page is for a person in a browser. An agent does not open it. `POST /agent-proof` is unchanged.

## Destination name

The page names where the person will return. That name is computed for the request. The page source does not contain a fixed host.

`audience` is an origin. `return` is a URL whose origin equals `audience`. Both are already required before this page is shown.

The destination name is chosen in this order:

1. When the query includes a non-empty `site`, the destination name is that `site` value.
2. Otherwise the destination name is the hostname of the `audience` origin. The hostname has no scheme and no port. An audience of `https://friends.example` shows `friends.example`. An audience whose host is an IP address shows that IP address.

An empty `site` parameter does not replace the hostname. The destination name is inserted as text. Characters that are special in HTML are escaped.

## The page

The document title and the heading are `Sign in`.

Under the heading, one sentence:

`To continue to {destination}, choose an account. You sign in on that site, then come back here.`

`{destination}` is the destination name.

Under the sentence, one button for each configured provider, in this order: Google, Apple, Facebook. A provider with no client id is absent. The buttons are rectangles of one shared width and one shared height. Each button shows that provider's standard mark, then the label. The mark comes before the words. The visible label is the accessible name.

The labels are:

- `Continue with Google`
- `Continue with Apple`
- `Continue with Facebook`

The buttons are Signet's own links. They do not load a provider SDK, and they do not use a provider webfont. The marks are files Signet serves. A button does not point its mark at the provider's website.

Use the official mark from the page below. Do not redraw it, recolor it, or take a mark from a web search. The three buttons stay one width and one height. Scale a mark without stretching it.

- Google. Follow [Sign in with Google Branding Guidelines](https://developers.google.com/identity/branding-guidelines). Use the standard color G from the pre-approved icon download on that page. The label stays `Continue with Google`.
- Apple. Follow [Sign in with Apple](https://developer.apple.com/sign-in-with-apple) and [Sign in with Apple buttons](https://developer.apple.com/design/human-interface-guidelines/sign-in-with-apple). Use the official Apple logo artwork. The label stays `Continue with Apple`. Do not use Sign in with Apple JS. That script talks to Apple on its own and skips `/auth/apple`.
- Facebook. Follow [Facebook Login user experience](https://developers.facebook.com/docs/facebook-login/userexperience). The mark is the current "f" logo from the [Facebook brand resources](https://www.meta.com/brand/resources/facebook/logo/), in Facebook blue `#1877F2` with a white "f", or in black and white when the blue cannot be used. The label stays `Continue with Facebook`. That logo pack is behind an acceptance step in the browser. If the official file is not already in the repo, stop and ask for it. Do not substitute another "f".

Each button's URL is the existing `/auth/{provider}` path, with the same `audience`, `return`, and `site` query this page received.

When test login is enabled, the existing `Sign in` form stays on the page in addition to any provider buttons. A public host leaves test login unset.

When no provider is configured and test login is off, the page does not show an empty list. It shows the heading, this sentence, and the warning code `no-provider`. It shows no provider button.

`Sign-in is not set up.`

`no-provider` is the only warning code on this page. The administrator guide lists it and says what to set. A client secret with no client id does not count as configured, so that case shows this same code.

## After a successful sign-in

The short page before the return stays. Its sentence becomes:

`Signed in as {label}. Taking you back to {destination}.`

`{label}` is the session label already used today. `{destination}` follows the same rule as the sign-in page. The page still waits about one second, then redirects to the return URL. The proof is still in the `#signet-proof=` fragment.

## When sign-in does not finish

A provider refusal or a failed exchange still redirects to the return URL with `#signet-identity=failed`. That fragment does not change. The sign-in page does not render that failure. The caller that reads the fragment can send the person back to `/connect`.

## Unchanged

Proof claims, the signing key, the derivation key, the session cookie, the redirect URIs, and the Google, Apple, and Facebook token exchange stay as they are. Choosing a button still ends at that company's own site, where the person enters the password. Signet still has no password field.

## Tests

- With Google, Apple, and Facebook configured, the sign-in page contains the heading, the sentence, and the three labels. The sentence contains the hostname of the audience given in that request. It does not contain a host taken from anywhere else.
- With a non-empty `site`, the sentence contains that `site` value and does not contain the audience hostname.
- With only Google configured, the page contains `Continue with Google` and does not contain the Apple or Facebook labels.
- With no provider and test login off, the page contains `Sign-in is not set up.` and the warning code `no-provider`, and does not contain `/auth/google`, `/auth/apple`, or `/auth/facebook`. A configured page does not contain `no-provider`.
- With test login on and no provider, the page still contains the `Sign in` submit button and its `/test-login` action.
- A provider button's href starts with `/auth/{provider}` and carries the `audience` and `return` from the request. Its mark is a file this server serves, not a URL on the provider's site.
- A destination name that contains HTML-special characters is escaped in the page.
- The success page contains `Signed in as {label}. Taking you back to {destination}.` for both a bare audience and an audience with `site`.
- A failed exchange still redirects to the return URL with the fragment `#signet-identity=failed`.
