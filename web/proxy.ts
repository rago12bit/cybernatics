import { NextRequest, NextResponse } from "next/server";

// Per-request nonce CSP (threat T9: stored XSS via scanned code in the report UI).
// Scripts run only if they carry the nonce; there is no 'unsafe-inline' for scripts or styles.
export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const isDev = process.env.NODE_ENV === "development";
  const demoOnly = process.env.NEXT_PUBLIC_DEMO_ONLY === "1";
  const api = (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000").replace(/\/$/, "");
  const ws = api.replace(/^http/, "ws");
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    // Dev only: Next's overlay injects inline styles. A nonce would make browsers ignore
    // 'unsafe-inline', so dev uses one or the other; production is nonce-only (no inline styles).
    isDev ? "style-src 'self' 'unsafe-inline'" : `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data:",
    "font-src 'self'",
    // The public sample build talks to nothing but itself.
    demoOnly ? "connect-src 'self'" : `connect-src 'self' ${api} ${ws}${isDev ? " ws://localhost:* http://localhost:*" : ""}`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");

  const headers = new Headers(request.headers);
  headers.set("x-nonce", nonce);
  headers.set("Content-Security-Policy", csp);
  const response = NextResponse.next({ request: { headers } });
  response.headers.set("Content-Security-Policy", csp);
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("Referrer-Policy", "no-referrer");
  response.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  // Week 48 task 2 (plan §22.3): found by running the platform's own ZAP baseline scan against
  // itself. Safe to add unconditionally -- this app loads no cross-origin fonts/images/scripts
  // (the CSP above already restricts font-src/img-src to 'self'), which is exactly the case where
  // require-corp has nothing to break. Verified live: a full page load plus every console message
  // checked clean before and after, with a real browser, not just ZAP's own report.
  response.headers.set("Cross-Origin-Embedder-Policy", "require-corp");
  response.headers.set("Cross-Origin-Opener-Policy", "same-origin");
  // Consistent with the CSP's frame-ancestors 'none' above: this app never expects to be embedded
  // by, or share its resources with, another origin.
  response.headers.set("Cross-Origin-Resource-Policy", "same-origin");
  if (demoOnly) response.headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  return response;
}

export const config = {
  matcher: [{ source: "/((?!_next/static|_next/image|favicon.ico).*)" }],
};
