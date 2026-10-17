# Sign-in, people and access

People sign in to Bulwark with your organization's identity provider (OIDC or SAML), are added and
removed by it over SCIM, and have a role in the organization, with higher roles on some business
units or projects when they need them. Scripts and CI use API tokens. Design and reasoning:
[ADR-0058](adr/0058-identity-sso-scim-roles.md).

## Roles

| Role | May |
|---|---|
| Admin | everything a member may, and run the organization: people and roles, sign-in, SCIM, rules, integrations (where findings and tickets go) and data retention |
| Member | scan, triage, import reports, request fixes and risk acceptances |
| Viewer | read |
| Only granted projects | see nothing but the business units and projects given to them |

A role on a business unit or a project only adds to the organization role. A business unit's role
covers all its projects. To give a contractor one project, make their organization role "Only
granted projects" and give them that project. They will see that project, the Issues list (with
only that project in it), saved views and their own things; dashboards, reports and other
organization-wide pages are for people with an organization role.

Change roles in **Settings → People and access**. Every change is in the audit log.

## The first admin

Before anyone can sign in, make the first admin on the server:

```bash
bulwark users add --org-id <organization id> --email you@example.com --role admin
```

They then sign in with your identity provider and set up everything else in the app. (The server's
shared `BULWARK_API_TOKEN` can do all of this too.)

## Server settings

| Variable | What |
|---|---|
| `BULWARK_PUBLIC_URL` | the web app's address, where a finished sign-in lands (e.g. `https://bulwark.example.com`) |
| `BULWARK_API_PUBLIC_URL` | the API's address, which identity providers call back (e.g. `https://api.bulwark.example.com`) |
| `BULWARK_CORS_ORIGINS` | the web app's origin, exactly; sign-in cookies need it |
| `BULWARK_SESSION_COOKIE_SECURE` | `true` (default). Set `false` only for plain-HTTP local development |

Postgres 16 or later is needed (migration 0048).

## Single sign-on with OIDC

In **Settings → Sign-in and provisioning**, choose **Add an OIDC provider** and give its issuer, the
client id and secret your provider gave Bulwark, and the email domains it signs in. Give the
provider the **redirect URI** the screen shows. Bulwark reads the provider's own description when
you save, and refuses one that names a different issuer.

| Provider | Issuer | Notes |
|---|---|---|
| Google Workspace | `https://accounts.google.com` | an OAuth client of type "Web application" |
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant id>/v2.0` | Entra sends no `email_verified`: tick "Trust the provider's emails" |
| Okta | `https://<your org>.okta.com` (or a custom authorization server's) | an OIDC web app |
| Keycloak | `https://<host>/realms/<realm>` | a confidential client; PKCE method S256 |

Every sign-in uses PKCE. The provider's ID token is checked strictly -- its signature, issuer,
audience, expiry and the nonce of that sign-in -- and anything else is refused.

### Google for any Google account

A provider can sign in **every** email domain: give `*` as its only domain. With Google that means
any Google account -- Gmail, or a school or company whose mail is on Google -- but **only for people
you have added** in **Settings → People and access**: an email nobody added is refused, and no
account is ever created for it, so *A first sign-in creates the account* cannot be ticked with `*`.
A domain that has its own provider still signs in with that one; `*` is only for the rest. Only one
provider can be `*`, and not in hosted mode, where it would catch other organizations' sign-ins.

At Google (Google Cloud console, with your own Google account):

1. **APIs & Services → OAuth consent screen**: user type **External**; the scopes `openid`, `email`
   and `profile` need no review. While it is **Testing**, only the test users you list can sign in;
   choose **Publish app** to let any Google account through to Bulwark's own check.
2. **Credentials → Create credentials → OAuth client ID**: type **Web application**; under
   **Authorized redirect URIs** add the redirect URI the Bulwark screen shows
   (`http://localhost:8000/auth/oidc/callback` locally: Google accepts plain HTTP for `localhost`).
3. In Bulwark: **Add an OIDC provider**, issuer `https://accounts.google.com`, the client ID and
   secret Google showed, email domains `*`.

## Single sign-on with SAML

Choose **Add a SAML provider** and paste your provider's metadata (or its entity ID, sign-in URL and
signing certificate). Give your provider Bulwark's **entity ID** and **assertion consumer service
URL** from the screen, or our metadata at the entity ID's address. Your provider must **sign its
assertions**: Bulwark refuses unsigned ones, and responses it did not ask for.

## Who is who

The first time someone signs in, Bulwark remembers the provider's stable id for them. After that,
that id decides who they are, so another account at the provider with the same email cannot become
them. Their email must be in one of the provider's domains. If **A first sign-in creates the
account** is off, only people already added (by an admin or by SCIM) can sign in.

Sessions last at most 12 hours, and end after 2 hours unused.

## Provisioning with SCIM

Make a **SCIM token** in **Settings → Sign-in and provisioning** and give it, with the **SCIM base
URL** shown there, to your identity provider's provisioning settings. Your provider then adds people
(as viewers, unless it sends a role), changes them, and turns them off. Someone it turns off is
signed out everywhere in the same moment, and every API token they made stops working.

Supported: Users (create, read, list with `filter=userName eq "..."`, replace, patch, delete). Not
supported: Groups and bulk requests.

## API tokens

**Settings → My API tokens** makes a token for CI or a script. It acts as you, with the scopes you
give it -- never more than your role allows at the time it is used -- and stops working when you are
turned off. It is shown once.

## API

```text
GET  /auth/sso/discover?email=           the provider for an email's domain
GET  /auth/sso/{id}/start?next=          start a sign-in
GET  /auth/session                       who is signed in, and the CSRF token
POST /auth/logout
GET|POST /v2/users, GET|PATCH /v2/users/{id}, PUT /v2/users/{id}/roles
GET|POST /v2/sso/providers, GET|PATCH|DELETE /v2/sso/providers/{id}, POST .../{id}/test
GET|POST /v2/scim/tokens, DELETE /v2/scim/tokens/{id}
GET|POST /v2/me/tokens, DELETE /v2/me/tokens/{id}
/scim/v2/Users ...                       for your identity provider
```
