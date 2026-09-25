// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FindingsTable } from "../components/FindingsTable";
import type { Finding, FindingsPage, FindingsQuery, ScanView } from "../lib/types";
import demo from "../lib/demo-data.json";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
Element.prototype.scrollIntoView = () => undefined; // jsdom has no layout
const scan = demo.scan as unknown as ScanView;
const all = demo.findings as unknown as Finding[];
let root: Root | null = null;

async function mount(fetchFindings: (id: string, q: FindingsQuery, limit?: number) => Promise<FindingsPage>) {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<FindingsTable scan={scan} version={0} fetchFindings={fetchFindings} />));
  await act(async () => { await new Promise((r) => setTimeout(r, 200)); });
  return host;
}
const withRisk = (f: Finding, risk: number): Finding => ({ ...f, scoring: { ...f.scoring, risk_score: risk } });
afterEach(async () => { await act(async () => root?.unmount()); root = null; document.body.innerHTML = ""; window.history.replaceState(null, "", "/"); });
beforeEach(() => window.history.replaceState(null, "", "/"));

describe("findings table behaviour", () => {
  it("keeps the router's history state when it syncs filters into the URL (Back/Forward must not reload)", async () => {
    window.history.replaceState({ __NA: true, tree: ["x"] }, "", "/scans/abc");
    const host = await mount(async () => ({ total: all.length, limit: 50, offset: 0, items: all.slice(0, 50) }));
    await act(async () => host.querySelector<HTMLButtonElement>(".filter.sev-high")!.click());
    expect(window.location.search).toContain("sev=HIGH");
    expect(window.history.state).toEqual({ __NA: true, tree: ["x"] });
  });

  it("lands on the last page when the link points past the end, instead of 'No findings match'", async () => {
    window.history.replaceState(null, "", "/?p=99");
    const fetcher = vi.fn(async (_id: string, q: FindingsQuery): Promise<FindingsPage> => ({ total: 38, limit: 50, offset: q.page * 50, items: q.page === 0 ? all : [] }));
    const host = await mount(fetcher);
    expect(host.textContent).not.toContain("No findings match");
    expect(host.querySelectorAll(".findings-table tbody tr").length).toBe(38);
    expect(window.location.search).not.toContain("p=");
  });

  it("prev/next follow the 'Fix these first' order when a finding is opened from there", async () => {
    const ranked = all.slice(0, 5).map((f, i) => withRisk(f, 90 - i * 10));
    const table = [...ranked].reverse(); // the table's own order is different on purpose
    const fetcher = async (_id: string, q: FindingsQuery): Promise<FindingsPage> => ({ total: 5, limit: 50, offset: 0, items: q.sort === "risk" ? ranked : table });
    const host = await mount(fetcher);
    await act(async () => host.querySelector<HTMLButtonElement>(".fixlist button.row-title")!.click());
    const sheet = () => host.querySelector("aside.sheet")!;
    expect(sheet().textContent).toContain(ranked[0]!.title.slice(0, 20));
    expect(sheet().textContent).toContain("1 of 5");
    await act(async () => sheet().querySelector<HTMLButtonElement>("button[aria-label^='Next']")!.click());
    expect(sheet().textContent).toContain("2 of 5");
    expect(sheet().querySelector("h3")!.textContent).toBe(ranked[1]!.title);
  });

  it("shows risk next to severity in one row, and orders rows the way the server sent them", async () => {
    const rows = [withRisk(all[0]!, 88), withRisk(all[1]!, 12)];
    const host = await mount(async () => ({ total: 2, limit: 50, offset: 0, items: rows }));
    const first = host.querySelector(".findings-table tbody tr")!;
    expect(first.querySelector(".sevcell .risk")?.textContent).toBe("88");
  });
});
