// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ScanComparison } from "../components/ScanComparison";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | null = null;

const overview = {
  asset: { id: "a1", label: "acme/widgets", source_type: "git", last_scanned_at: "2026-09-01T00:00:00Z", latest_scan_id: "s2", latest_scan_status: "completed", open_issue_count: 1 },
  verdict_count: 0, fix_first: [], more_at_lower_risk: 0,
  since_previous_scan: { fixed: 0, new: 0, returned: 0 },
  trend: [
    { scan_id: "s1", finished_at: "2026-09-01T00:00:00Z", open_count: 2 },
    { scan_id: "s2", finished_at: "2026-09-02T00:00:00Z", open_count: 1 },
  ],
  scanned: [], latest_scan_id: "s2", latest_scan_finished_at: "2026-09-02T00:00:00Z",
};

const comparison = {
  earlier: { scan_id: "s1", source_label: "acme/widgets", finished_at: "2026-09-01T00:00:00Z", github_pr_number: null },
  later: { scan_id: "s2", source_label: "acme/widgets", finished_at: "2026-09-02T00:00:00Z", github_pr_number: 7 },
  new: [{ id: "i-new", title: "New SQL injection", severity: "HIGH", category: "sast", path: "a.py" }],
  fixed: [{ id: "i-fixed", title: "Old XSS", severity: "MEDIUM", category: "sast", path: "b.py" }],
  reintroduced: [],
  unchanged: [{ id: "i-same", title: "Known secret", severity: "CRITICAL", category: "secrets", path: "c.env" }],
};

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

async function mount() {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<ScanComparison assetId="a1" />));
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
  return host;
}

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("ScanComparison", () => {
  it("compares the two most recent scans by default and renders every category", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (url.includes("/overview")) return json(overview);
      expect(url).toContain("/scans/s2/compare?against=s1");
      return json(comparison);
    });
    vi.stubGlobal("fetch", fetchMock);
    const host = await mount();
    expect(host.textContent).toContain("New SQL injection");
    expect(host.textContent).toContain("Old XSS");
    expect(host.textContent).toContain("Known secret");
    expect(host.textContent).toMatch(/Nothing came back/);
  });

  it("re-fetches the comparison when the picker changes", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (url.includes("/overview")) return json(overview);
      if (url.includes("against=s2")) return json({ ...comparison, new: [] });
      return json(comparison);
    });
    vi.stubGlobal("fetch", fetchMock);
    const host = await mount();
    const [earlierSelect, laterSelect] = Array.from(host.querySelectorAll("select"));
    expect(laterSelect!.value).toBe("s2");
    await act(async () => {
      earlierSelect!.value = "s2";
      earlierSelect!.dispatchEvent(new Event("change", { bubbles: true }));
    });
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50));
    });
    const calls = fetchMock.mock.calls.map((c) => String(c[0]));
    expect(calls.some((u) => u.includes("against=s2"))).toBe(true);
  });

  it("says so when a project has fewer than two scans", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json({ ...overview, trend: [overview.trend[0]] })));
    const host = await mount();
    expect(host.textContent).toMatch(/needs at least two finished scans/);
  });

  it("shows a readable error when the overview fails to load", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ detail: "not found" }), { status: 404 })));
    const host = await mount();
    expect(host.querySelector("[role=alert]")?.textContent).toBe("not found");
  });
});
