// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CostDashboard } from "../components/CostDashboard";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | null = null;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function mount() {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<CostDashboard />));
  await act(async () => {
    await new Promise((r) => setTimeout(r, 20));
  });
  return host;
}

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("CostDashboard", () => {
  it("shows an empty state when there are no scans in the window", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        json({
          days: 30, scan_count: 0, total_compute_seconds: 0, total_llm_tokens: 0,
          total_compute_usd: 0, total_llm_usd: 0, total_usd: 0, scans: [],
        }),
      ),
    );
    const host = await mount();
    expect(host.textContent).toContain("No scans in this window.");
  });

  it("renders the aggregate totals and per-scan rows from a real-shaped response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        json({
          days: 30, scan_count: 1, total_compute_seconds: 12.5, total_llm_tokens: 2000,
          total_compute_usd: 0.00375, total_llm_usd: 0.012, total_usd: 0.01575,
          scans: [
            {
              scan_id: "s1", source_label: "https://github.com/octocat/Hello-World",
              created_at: "2026-10-01T00:00:00Z", compute_seconds: 12.5, llm_tokens: 2000,
              total_usd: 0.01575,
            },
          ],
        }),
      ),
    );
    const host = await mount();
    expect(host.textContent).toContain("2,000 tokens");
    const link = host.querySelector('a[href="/scans/s1"]');
    expect(link).not.toBeNull();
    expect(link?.textContent).toBe("https://github.com/octocat/Hello-World");
  });

  it("switches the window and refetches with the new days value", async () => {
    const urls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        urls.push(url);
        return json({
          days: 30, scan_count: 0, total_compute_seconds: 0, total_llm_tokens: 0,
          total_compute_usd: 0, total_llm_usd: 0, total_usd: 0, scans: [],
        });
      }),
    );
    const host = await mount();
    const btn = Array.from(host.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("Last 7d"),
    )!;
    await act(async () => btn.click());
    await act(async () => {
      await new Promise((r) => setTimeout(r, 20));
    });
    expect(urls.some((u) => u.includes("days=7"))).toBe(true);
  });

  it("shows an error when the summary fails to load", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json({ detail: "boom" }, 500)));
    const host = await mount();
    expect(host.querySelector('[role="alert"]')).not.toBeNull();
  });
});
