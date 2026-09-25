// @vitest-environment jsdom
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({ usePathname: () => "/", useRouter: () => ({ push: () => undefined }) }));

async function markup(flag: string) {
  vi.stubEnv("NEXT_PUBLIC_DEMO_ONLY", flag);
  vi.resetModules();
  const { Landing } = await import("../components/site/Landing");
  const { DemoReport } = await import("../components/DemoReport");
  return renderToStaticMarkup(<Landing />) + renderToStaticMarkup(<DemoReport />);
}
afterEach(() => vi.unstubAllEnvs());

describe("public sample build (NEXT_PUBLIC_DEMO_ONLY=1)", () => {
  it("never points a visitor at the app, the API or localhost", async () => {
    const html = await markup("1");
    expect(html).not.toMatch(/href="\/app"/);
    expect(html).not.toContain("localhost");
    expect(html).not.toContain(":8000");
    expect(html).toContain('href="/self-host"');
    expect(html).toContain("Run it yourself");
  });

  it("the normal build still links to the app and the API docs", async () => {
    const html = await markup("0");
    expect(html).toContain('href="/app"');
    expect(html).toContain("/docs");
    expect(html).not.toContain('href="/self-host"');
  });

  it("the self-host page explains why there is no hosted scanner", async () => {
    const { default: SelfHost } = await import("../app/self-host/page");
    const html = renderToStaticMarkup(<SelfHost />);
    expect(html).toContain("Scanning happens on your machine");
    expect(html).toContain("docker compose up -d");
    expect(html).toMatch(/licence/);
  });
});

describe("public links are opt-in and validated", () => {
  it("accepts https repo links and mailto contacts, rejects everything else", async () => {
    const { safePublicLink } = await import("../lib/site");
    expect(safePublicLink("https://example.com/me/bulwark", false)).toBe("https://example.com/me/bulwark");
    expect(safePublicLink("mailto:someone@example.com", true)).toBe("mailto:someone@example.com");
    for (const bad of ["", undefined, "javascript:alert(1)", "http://example.com", "https://u:p@example.com", "data:text/html,x", "not a url"]) {
      expect(safePublicLink(bad, true)).toBeNull();
    }
    expect(safePublicLink("mailto:someone@example.com", false)).toBeNull(); // repo links are never mailto
    expect(safePublicLink("mailto:a b@example.com", true)).toBeNull();
  });

  it("shows no repo or contact link unless configured", async () => {
    const html = await markup("1");
    expect(html).not.toContain("Source code");
    expect(html).not.toContain("Contact");
  });

  it("shows them, as external links, when configured", async () => {
    vi.stubEnv("NEXT_PUBLIC_REPO_URL", "https://example.com/me/bulwark");
    vi.stubEnv("NEXT_PUBLIC_CONTACT_URL", "mailto:me@example.com");
    const html = await markup("1");
    expect(html).toContain('href="https://example.com/me/bulwark"');
    expect(html).toContain('href="mailto:me@example.com"');
    expect(html).toContain('rel="noopener noreferrer"');
  });
});
