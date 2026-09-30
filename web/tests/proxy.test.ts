import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { proxy } from "../proxy";

function req(path = "/"): NextRequest {
  return new NextRequest(new Request(`http://localhost:3000${path}`));
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("proxy (Week 48 task 2, plan §22.3: headers a real ZAP baseline scan checks for)", () => {
  it("sets every security header a ZAP baseline scan checks for", () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("NEXT_PUBLIC_DEMO_ONLY", "1");
    const res = proxy(req());
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(res.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(res.headers.get("Permissions-Policy")).toContain("camera=()");
    expect(res.headers.get("Cross-Origin-Embedder-Policy")).toBe("require-corp");
    expect(res.headers.get("Cross-Origin-Opener-Policy")).toBe("same-origin");
    expect(res.headers.get("Cross-Origin-Resource-Policy")).toBe("same-origin");
  });

  it("sets a nonce-based CSP with no 'unsafe-inline' for scripts or styles in production", () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("NEXT_PUBLIC_DEMO_ONLY", "1");
    const res = proxy(req());
    const csp = res.headers.get("Content-Security-Policy") ?? "";
    expect(csp).toMatch(/script-src 'self' 'nonce-[^']+' 'strict-dynamic'/);
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("object-src 'none'");
  });

  it("allows 'unsafe-eval' and inline styles only in development, for Next's own dev overlay", () => {
    vi.stubEnv("NODE_ENV", "development");
    const res = proxy(req());
    const csp = res.headers.get("Content-Security-Policy") ?? "";
    expect(csp).toContain("'unsafe-eval'");
    expect(csp).toContain("style-src 'self' 'unsafe-inline'");
  });

  it("sets HSTS for the public demo-only build (always real HTTPS on Fly.io)", () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("NEXT_PUBLIC_DEMO_ONLY", "1");
    expect(proxy(req()).headers.get("Strict-Transport-Security")).toContain("max-age=");
  });

  it("does not set HSTS by default for a self-hosted deployment (may not be behind TLS at all)", () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("NEXT_PUBLIC_DEMO_ONLY", "0");
    expect(proxy(req()).headers.get("Strict-Transport-Security")).toBeNull();
  });

  it("sets HSTS for a self-hosted deployment that opts in with BULWARK_FORCE_HTTPS", () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("NEXT_PUBLIC_DEMO_ONLY", "0");
    vi.stubEnv("BULWARK_FORCE_HTTPS", "1");
    expect(proxy(req()).headers.get("Strict-Transport-Security")).toContain("max-age=");
  });

  it("generates a fresh nonce on every request", () => {
    // x-nonce itself is only forwarded on the rewritten REQUEST headers (so a Server Component can
    // read it via next/headers), never exposed as a response header -- the nonce is only visible to
    // the browser embedded inside the CSP header's own 'nonce-...' value.
    vi.stubEnv("NODE_ENV", "production");
    const extractNonce = (csp: string | null) => csp?.match(/'nonce-([^']+)'/)?.[1];
    const nonceA = extractNonce(proxy(req()).headers.get("Content-Security-Policy"));
    const nonceB = extractNonce(proxy(req()).headers.get("Content-Security-Policy"));
    expect(nonceA).toBeTruthy();
    expect(nonceA).not.toBe(nonceB);
  });
});
