# Deploying the public sample site

The public site is the **web app only, built in sample mode**: it serves the sample report and the About
page. It has no API, no database, no scanners, no sign-in and no secrets, so nothing untrusted ever runs on
it. This is deliberate: hosting real scanning needs the fixes listed in
[THREAT-MODEL.md](THREAT-MODEL.md#before-a-public-deployment) and a decision on
[ADR-006](adr/0006-semgrep-rules-licensing.md).

## What "sample mode" changes

Build with `NEXT_PUBLIC_DEMO_ONLY=1` (a build argument in `web/Dockerfile`):

| | Normal build | Sample build |
|---|---|---|
| `/` sample report, `/about` | yes | yes |
| `/app`, `/scans/*` | scanning UI | redirect (307) to `/self-host` |
| `/self-host` | n/a | how to run Bulwark locally, and why there is no hosted scanner |
| Header / hero buttons | "Open the app" | "Run it yourself" |
| API reference link | the API's `/docs` | `/self-host` (no API exists) |
| CSP `connect-src` | `'self'` + the API | `'self'` only |
| Extra headers | | `Strict-Transport-Security` |

Tests for this live in `web/tests/demo-only.test.tsx`. The flag is inlined at build time, so a sample build
contains no reference to an API address.

## Verified locally

The sample image was built and run: `/`, `/about`, `/self-host` return 200; `/app` and `/scans/x` redirect to
`/self-host`; `/demo` redirects to `/`; the container runs as a non-root user (uid 1000) and passes its
health check; the browser page contacts only its own origin, with a clean console; and no built file
contains `localhost:8000`. It has **not** been deployed to a real host from this repository.

```bash
docker build -t bulwark/web:demo --build-arg NEXT_PUBLIC_DEMO_ONLY=1 --build-arg NEXT_PUBLIC_API_URL= web
docker run --rm -p 127.0.0.1:3100:3000 bulwark/web:demo     # http://localhost:3100
```

## Fly.io

`web/fly.toml` is ready. You need a Fly account and `flyctl`.

```bash
cd web
fly launch --no-deploy --copy-config    # pick a free app name when asked (edit `app` in fly.toml)
fly deploy
```

It runs one 256 MB shared-CPU machine that stops when idle and starts on the next request (the first visit
after idle takes a few seconds). Fly terminates TLS and redirects http to https.

## Railway, Render, a VPS

Any host that runs a Dockerfile works: point it at `web/`, set the build argument
`NEXT_PUBLIC_DEMO_ONLY=1` (build-time, not a runtime variable), expose port 3000. On a VPS:

```bash
docker run -d --restart unless-stopped -p 127.0.0.1:3000:3000 bulwark/web:demo
```

and put a TLS-terminating proxy (Caddy or nginx) in front. Do not publish port 3000 directly to the internet
without TLS: the app sets HSTS assuming it is served over https.

## Checklist before you share the link

- [ ] Open the URL: the sample report loads and `/app` lands on "Scanning happens on your machine".
- [ ] `curl -sI https://YOUR-URL/ | grep -i content-security-policy` shows `connect-src 'self'`.
- [ ] The repository link and contact details you put on the site are ones you want public.
- [ ] Consider a custom domain; the default `*.fly.dev` name is fine for a CV.
