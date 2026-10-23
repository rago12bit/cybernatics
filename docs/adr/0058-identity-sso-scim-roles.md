# ADR-0058: Accounts with scoped roles; OIDC and SAML through checked libraries; SCIM; a guest database role

Status: Accepted (2026-10-07), Week 75 (plan §51). This is the plan's "ADR-022". Builds on
[ADR-0013](0013-tenancy-row-level-security.md) (RLS between organizations) and
[ADR-0018](0018-scoped-api-tokens.md) (scoped tokens).

## Context

Until now a person was an API token pasted into a browser tab, and each person picked their own
role (lead, engineer, tester) for their home page. Plan §51 asks for OIDC sign-in with PKCE and
strict issuer, audience and nonce checks; SAML 2.0 "through a maintained library only", tested
against signature wrapping, NameID comment injection and unsigned assertions; SCIM provisioning and
deprovisioning "so someone leaving the company loses access within minutes"; and organization roles
with per-portfolio and per-project overrides that cascade, proved by a two-project variant of the
two-tenant test.

## Decision

**Accounts.** A user belongs to one organization and has an organization role: admin, member,
viewer, or `none` (only what is granted). Overrides give a higher role on a business unit (reaching
its projects) or one project. They only raise access, as DefectDojo's product permissions do; to
give a contractor one project, their organization role is `none`. Roles become the token scopes the
API already checks, so each route keeps its one `require_scope(...)`: for a person, the scopes are
those of their role on the project the path names (project, scan, Issue, acceptance, engagement,
import, ...), else of their organization role. Organization-wide changes need an organization role;
someone limited to some projects can read only the project list, the cross-project Issues list, saved
views and their own things. A token a person makes acts as them, within its scopes and their role
when it is used. Users are `user:<id>` actors everywhere people were (assignment, mentions,
approvers); tokens from before accounts keep working as before.

**Sessions.** A sign-in creates a session: an HttpOnly, SameSite=Lax, Secure cookie with a random
secret, stored as its SHA-256; 12 hours at most, 2 hours idle. A change made with a session needs
its CSRF token in `X-Bulwark-CSRF`, which only this site's pages can read (`/auth/session`, over
CORS with an explicit origin list and credentials). Signing out, turning someone off and SCIM
deprovisioning end sessions at once. Evidence files are served with a sandboxing CSP, so a file that
runs script on the API's host cannot use the cookie.

**OIDC** is ours on PyJWT: the protocol is small and the checks are the point, so they are written
out and tested one by one (asymmetric algorithms only; exact issuer; audience and `azp`; expiry and
issue time with a minute's skew; the nonce; PKCE S256; one-time `state`; HTTPS to the provider except
on this machine). The provider's own description is read when it is saved and must name the issuer
configured.

**SAML** is pysaml2 with xmlsec1: assertions must be signed, unsolicited responses are refused, and
audience, destination and validity are pysaml2's checks. Bulwark never reads a SAML response itself.
The attack tests assert *why* each forgery is refused, so a test cannot pass on an unrelated error.

**Who signs in** is decided by the provider's stable subject (OIDC `sub`, SAML NameID), linked to the
account on the first sign-in: a second account at the provider with the same email cannot take
someone's place, and an email changed at the provider does not move them. The email must be in one
of the provider's domains and verified (OIDC), unless the provider is trusted for emails (Entra ID
sends no `email_verified`). A first sign-in creates the account only when the provider is set to.

**SCIM** (`/scim/v2/Users`) takes only a token with the `scim` scope, made for the provider and
belonging to no one. New people are viewers unless the provider sends a role. `active: false` or
DELETE turns the person off in the same request; DELETE also hides them from the provider while
keeping them for the audit trail, and provisioning them again restores the same account.

**Projects a person may not see are hidden by Postgres, not only by the app.** Their requests run as
the `bulwark_guest` role (`SET LOCAL ROLE`), whose restrictive RLS policies on `assets` and every
table that names a project -- directly, or through an Issue, a scan, an engagement or an engagement
test -- keep only the projects in `app.project_scope`. The service roles may switch to it but do
not inherit it (`WITH INHERIT FALSE, SET TRUE`, Postgres 16), because a policy applies to every role
whose privileges a session has.

## Alternatives tried

- **The same restrictive policies for every session** ("all projects, or this list"). Postgres
  estimated that such a policy let 2 of 200 projects through, and plans through `assets` collapsed:
  at a million Occurrences the organization-wide "past SLA" metric went from a 7 ms median to 224 ms
  (its list of the ten most overdue Issues took 666 ms under EXPLAIN ANALYZE). Limited to the guest
  role, the policies cost nothing for everyone else.
- **JIT compilation.** Turned off per transaction: on large counts it took 116 of 153 ms, and it was
  costing every large count before this week too (counting 100,000 Issues: 93 ms with, 44 ms without).

## Consequences

- Postgres 16 or later from migration 0048. xmlsec1 in the API image and in CI.
- Google Workspace, Entra ID and Okta are covered by standard OIDC (and Entra's missing claim by the
  trust setting), but only Keycloak was signed in through here.
- A person limited to some projects cannot make organization-wide changes, including bulk changes on
  the cross-project Issues list; on their own projects' pages they can.
- The first admin is made with `bulwark users add --role admin`, or by the shared token.
- The WebSocket for live scans authenticated with a pasted token only, so a signed-in browser was
  refused, and the scan page read the refusal as an expired session. Since 2026-10-23 it takes the
  session cookie (from a trusted origin only) and people's own tokens too, with `scans:read` on the
  scan's project, like `GET /scans/{id}`.
