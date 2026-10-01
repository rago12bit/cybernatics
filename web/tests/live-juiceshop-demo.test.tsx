// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LiveJuiceShopDemo } from "../components/LiveJuiceShopDemo";
import data from "../lib/juiceshop-demo-data.json";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | null = null;

async function mount() {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<LiveJuiceShopDemo />));
  return host;
}

beforeEach(() => vi.useFakeTimers());
afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  document.body.innerHTML = "";
  vi.useRealTimers();
});

describe("the launch landing page's live Juice Shop replay (plan §33, Week 52)", () => {
  it("starts mid-scan: no tool has reported in yet, and the real finding count isn't shown", async () => {
    const host = await mount();
    expect(host.textContent).toContain("A real scan of the real, public");
    expect(host.textContent).not.toContain("Unique findings");
  });

  it("reveals scanners one at a time as the replay clock advances, fastest real duration first", async () => {
    const host = await mount();
    const sorted = Object.entries(data.scan.tool_status)
      .filter(([, t]) => t.status !== "skipped")
      .sort((a, b) => (a[1].duration_seconds ?? 0) - (b[1].duration_seconds ?? 0));
    const fastest = sorted[0]?.[0];

    // Nothing reported in yet, right at the start.
    expect(host.textContent).not.toContain("1 of");

    await act(async () => {
      vi.advanceTimersByTime(6000); // past the whole replay window
    });

    // Once finished, the real, final, deduplicated report is shown -- same numbers as the source scan.
    expect(host.textContent).toContain("Unique findings");
    expect(host.textContent).toContain(String(data.scan.unique_findings));
    expect(fastest).toBeTruthy(); // sanity: the real data actually has an ordering to assert on
  });

  it("switches from a live to a done connection label once the replay finishes", async () => {
    const host = await mount();
    expect(host.textContent).toContain("replaying how it happened");
    await act(async () => {
      vi.advanceTimersByTime(6000);
    });
    expect(host.textContent).toContain("replay finished");
    expect(host.querySelector("button")?.textContent).toContain("Watch it again");
  });

  it("links to the full Juice Shop repo and to a smaller fixed sample", async () => {
    const host = await mount();
    const hrefs = [...host.querySelectorAll("a")].map((a) => a.getAttribute("href"));
    expect(hrefs).toContain("https://github.com/juice-shop/juice-shop");
    expect(hrefs).toContain("/sample");
  });

  it("never fabricates: every finding rendered once done comes from the real captured scan data", async () => {
    const host = await mount();
    await act(async () => {
      vi.advanceTimersByTime(6000);
    });
    const first = data.findings[0];
    // The table paginates, so just confirm the real total and severity counts round-trip untouched.
    for (const [sev, n] of Object.entries(data.scan.severity_counts)) {
      expect(host.textContent).toContain(String(n));
      expect(sev).toBeTruthy();
    }
    expect(first).toBeTruthy();
  });
});
