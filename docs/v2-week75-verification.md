# Week 75 verification: SSO, SCIM and scoped roles (plan §51)

Design: [ADR-0058](adr/0058-identity-sso-scim-roles.md) (the plan's ADR-022). How to set it up:
[Sign-in, people and access](identity.md). Threat model: T11 and T18.

Done before Week 74 at the owner's choice, so the usability study's participants sign in the way
people will.

## What was built

- **Accounts and roles** (migration 0048). People in an organization with a role -- admin, member,
  viewer, or only granted projects -- and higher roles on business units or projects that cascade
  down and only add access. Roles become the scopes the API already checks, decided per project from
  the request's path. Turning someone off ends their sessions and revokes their tokens at once.
  `bulwark users add|list|disable` for the first admin. People with accounts are people everywhere
  tokens were: assignment, mentions, approvers, rules' admins.
- **Sessions.** An HttpOnly, SameSite=Lax, Secure cookie; only its hash stored; 12 hours at most, 2
  idle; a CSRF token for every change.
- **OIDC with PKCE** (migration 0049), on PyJWT, every check written out: asymmetric signatures only,
  exact issuer, audience and `azp`, expiry, nonce, one-time state, HTTPS.
- **SAML 2.0 through pysaml2** with xmlsec1: signed assertions required, no unsolicited responses.
- **Who signs in** is the provider's stable subject, linked on the first sign-in.
- **SCIM 2.0** for Users, with a token only the provider holds; deprovisioning is immediate.
- **Two-project access in Postgres**: someone limited to some projects runs as the `bulwark_guest`
  role, whose restrictive policies hide every other project in every table that names one.
- **Web**: a sign-in screen that asks for a work email and sends the person to their provider (an API
  token remains an option), **People and access**, **Sign-in and provisioning** (providers, the URLs
  to give them, SCIM tokens), **My API tokens**.

## Checked against real systems

- **Keycloak 26.3**, locally (`quay.io/keycloak/keycloak:26.3`, bound to 127.0.0.1):
  - `tests/integration/test_sso_keycloak_live.py`: a realm, an OIDC client requiring PKCE S256 and a
    SAML client signing assertions; through Keycloak's own sign-in form, both end with a Bulwark
    session for that person; a wrong password signs nobody in.
  - In the browser: the app's sign-in screen took `alice@acme.test`, sent the browser to Keycloak
    (the URL carried `code_challenge_method=S256`), and after Keycloak's form landed back on the page
    it started from, with no token in the tab, the session cookie unreadable to the page, and 174
    Issues loaded with it. An admin change (a project role for a contractor) went through with the
    cookie and the CSRF token only. Signing out ended the session on the server (the next request:
    401) and showed the sign-in screen again.
- **Postgres 16 under forced RLS** (a throwaway container):
  - Migrations 0048 and 0049 down and up. 34 project-scope policies, all for `bulwark_guest`; the
    service roles may switch to it but do not inherit it.
  - The two-project test: a session limited to one project sees its project, Issues, scans, findings,
    SLA policies and metric rows and none of the other project's acceptances, engagements, notes or
    rows; cannot change the other project's Issues; with nothing granted sees nothing; and a session
    with every project is not in the guest role at all. It fails when the policy on `assets` is
    loosened. Through the API too: a contractor's cookie lists only their project and gets 404 for
    the other's pages.
  - An OIDC sign-in through the API on Postgres, as the API's role; the other organization sees
    neither the provider, the person, nor their linked identity.
  - All 69 RLS tests pass.
- **Speed**, on a fresh Postgres: worst search p95 at 100,000 Issues **93 ms**; worst dashboard metric
  p95 at a million Occurrences **120 ms**. Two problems found and fixed on the way are in the ADR and
  `benchmarks/README.md`: policies for every session made the "past SLA" metric 30 times slower, and
  JIT compilation was slowing every large count.

## Tests

- **Backend:** 10 account tests (sessions and CSRF, short sessions, roles, overrides on projects and
  units, the guest limited to some projects, turning someone off, a person's token never above their
  role, people everywhere, old tokens unchanged); 23 OIDC tests against a fake provider with its own
  key (a whole sign-in with PKCE checked by the provider, eleven wrong tokens including `alg: none`,
  another key and HMAC with the public key, key rotation, replayed and expired callbacks, never
  landing on another site, who the provider's word makes you, Entra's missing claim, settings); 13
  SAML tests against pysaml2's own IdP, each asserting the reason for the refusal (unsigned, another
  key, tampered, three kinds of signature wrapping, NameID comment injection, another service,
  unsolicited and crossed, expired, replayed, metadata including a billion-laughs document); 7 SCIM
  tests (Okta- and Entra-shaped requests, access ended in the same request, delete and come back, the
  last admin, the provider's token does only SCIM, other organizations).
- **Web:** 7 tests with axe (sign-in by email, the no-SSO path, the error page, a session's CSRF
  header on a change, People and access, sign-in settings with a SCIM token shown once, My API
  tokens). The four Playwright journeys sign in through the new screen and pass; the three visual
  baselines pass unchanged. axe on the new pages at 1,440 and 375 px: clean, after removing a nested
  `<main>` on the sign-in page; nothing scrolls sideways.

## Not done, or not proven

- **Google Workspace, Entra ID and Okta were not signed in through**: standard OIDC covers them, and
  Entra's missing `email_verified` has a setting, but only Keycloak was exercised.
- **SCIM Groups** are not supported; a role can come with the user (`roles`), and admins change roles
  in the app.
- **The shared token stays**, with every scope, for the operator and automation; so do tokens from
  before accounts, with their own scopes.
- **Signed-in browsers have no live WebSocket** for a running scan: it authenticates with a pasted
  token. They fall back to polling every three seconds, as the scan page already did.
- **One organization per person**: someone in two organizations has two accounts.
- **Someone limited to some projects** cannot make organization-wide changes, bulk changes included.
