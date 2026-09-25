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
