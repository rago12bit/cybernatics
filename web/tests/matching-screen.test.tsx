// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MatchingScreen } from "../components/MatchingScreen";
import type { DedupOverview, DedupPreview } from "../lib/types";

vi.mock("next/navigation", () => ({ usePathname: () => "/app", useRouter: () => ({ push: vi.fn() }) }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const ASSET = "11111111-1111-4111-8111-111111111111";

const OVERVIEW: DedupOverview = {
  default: "fingerprint_v2",
  strategies: [
    { name: "fingerprint_v2", description: "the location-independent fingerprint" },
    { name: "tool_id", description: "the scanner's own rule id, and where it was found" },
    { name: "hash_fields", description: "a hash of the fields you choose" },
    { name: "tool_id_or_hash", description: "the rule id and place, or chosen fields" },
    { name: "package", description: "ecosystem, package, version and vulnerability id" },
  ],
  fields: ["title", "severity", "cwe", "path", "host", "route"],
  sources: [
    { source: "nessus", strategy: "fingerprint_v2", fields: [], version: 0, recommended: "tool_id",
      issues_seen: 212, changed_at: null, changed_by: null, effect: {} },
    { source: "zap", strategy: "tool_id", fields: [], version: 2, recommended: "tool_id",
      issues_seen: 40, changed_at: "2026-10-04T10:00:00Z", changed_by: "ana", effect: { merged_away: 3 } },
  ],
};

function preview(over: Partial<DedupPreview> = {}): DedupPreview {
  return {
    source: "nessus", from: { strategy: "fingerprint_v2", version: 0 },
    to: { strategy: "tool_id", version: 1, fields: [] },
    summary: "Switching nessus to tool_id would merge 115 issues into 18 and split none",
    issues_before: 212, issues_after: 97, merge_groups: 18, issues_merged_away: 115, issues_split: 0,
    new_issues_from_split: 0, skipped_multi_source: 0, triage_conflicts: 0, conflicts: [],
    examples: [{ kind: "merge", issues: ["a", "b"], issue_count: 2, titles: ["SSL cipher suites"], occurrences: 2 }],
    digest: "d".repeat(32), changes_anything: true, ...over,
  };
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

type Call = { method: string; path: string; body?: Record<string, unknown> };

function api(opts: { preview?: DedupPreview; apply?: () => Response; overview?: DedupOverview } = {}) {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const path = new URL(String(url)).pathname;
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ method, path, body });
    const base = `/v2/projects/${ASSET}/dedup`;
    if (path === base && method === "GET") return json(opts.overview ?? OVERVIEW);
    if (path === `${base}/preview`) return json(opts.preview ?? preview());
    if (path === `${base}/apply`)
      return opts.apply?.() ?? json({ source: "nessus", version: 1, effect: { merged_away: 115, created_by_split: 0 }, summary: "x" });
    if (path === `${base}/history`)
      return json([{ source: "zap", version: 2, strategy: "tool_id", fields: [], note: "stable ids", created_by: "ana",
        created_at: "2026-10-04T10:00:00Z", effect: { merged_away: 3, created_by_split: 0 } }]);
    return json({}, 404);
  }));
  return calls;
}

let root: Root | null = null;
const flush = (ms = 30) => act(async () => { await new Promise((r) => setTimeout(r, ms)); });

async function mount() {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<MatchingScreen assetId={ASSET} />));
  await flush();
  return host;
}
const click = (el: Element) => act(async () => { (el as HTMLElement).click(); });
const byText = (host: HTMLElement, text: string) =>
  Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.trim().startsWith(text)) as HTMLButtonElement;

async function openNessus(host: HTMLElement) {
  await click(byText(host, "Change matching for nessus") ?? host.querySelectorAll(".ds-match-link")[0]);
  await flush();
}
async function previewTo(host: HTMLElement, strategy = "tool_id") {
  await openNessus(host);
  await click(host.querySelector(`input[value="${strategy}"]`)!);
  await click(byText(host, "Preview the change"));
  await flush();
}

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

async function violations(el: Element) {
  const r = await axe.run(el, { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } });
  return r.violations.map((v) => `${v.id}: ${v.nodes.slice(0, 2).map((n) => n.target.join(" ")).join(" | ")}`);
}

describe("MatchingScreen", () => {
  it("lists each source with its strategy, version and what is suggested, as a real table", async () => {
    api();
    const host = await mount();
    const table = host.querySelector("table.ds-match-table")!;
    expect(table.querySelector("caption")?.textContent).toBe("Matching strategy by source");
    const rows = Array.from(table.querySelectorAll("tbody tr")).map((r) =>
      Array.from(r.children).map((c) => c.textContent?.replace(/\s+/g, " ").trim()));
    expect(rows[0]!.slice(0, 5)).toEqual(["nessus", "Fingerprint (the default)", "default", "212", "Tool ID"]);
    expect(rows[1]!.slice(0, 5)).toEqual(["zap", "Tool ID", "v2", "40", "Tool ID"]);
    expect(await violations(host)).toEqual([]);
  });

  it("says nothing changes until confirmed, and offers no way to apply before a preview", async () => {
    api();
    const host = await mount();
    expect(host.textContent).toContain("nothing changes until you confirm");
    await openNessus(host);
    expect(byText(host, "Apply this change")).toBeUndefined();
    expect(byText(host, "Preview the change")).toBeDefined();
  });

  it("shows the server's sentence and counts, and applies exactly the previewed change", async () => {
    const calls = api();
    const host = await mount();
    await previewTo(host);
    const pv = calls.find((c) => c.path.endsWith("/preview"))!;
    expect(pv.body).toEqual({ source: "nessus", strategy: "tool_id", fields: [] });
    expect(host.querySelector(".ds-match-summary")?.textContent).toBe(
      "Switching nessus to tool_id would merge 115 issues into 18 and split none.");
    const counts = Array.from(host.querySelectorAll(".ds-match-counts tr")).map((r) => r.textContent);
    expect(counts).toContain("Issues now212");
    expect(counts).toContain("Issues after97");
    expect(host.textContent).toContain("Occurrences are never lost");

    const note = host.querySelector("textarea") as HTMLTextAreaElement;
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!.call(note, "stable ids");
      note.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await click(byText(host, "Apply this change"));
    await flush();
    const ap = calls.find((c) => c.path.endsWith("/apply"))!;
    expect(ap.method).toBe("POST");
    expect(ap.body).toEqual({ source: "nessus", strategy: "tool_id", fields: [], digest: "d".repeat(32), note: "stable ids" });
    expect(host.querySelector(".ds-match-done")?.textContent).toContain("115 Issues merged away");
    expect(host.querySelector(".ds-match-panel")).toBeNull(); // closed, and the table reloaded
    expect(calls.filter((c) => c.path.endsWith("/dedup") && c.method === "GET").length).toBe(2);
  });

  it("drops a preview as soon as the choice changes, so a stale one can never be applied", async () => {
    api();
    const host = await mount();
    await previewTo(host);
    expect(byText(host, "Apply this change")).toBeDefined();
    await click(host.querySelector('input[value="hash_fields"]')!);
    expect(host.querySelector(".ds-match-preview")).toBeNull();
    expect(byText(host, "Apply this change")).toBeUndefined();
  });

  it("asks for a field before previewing a hash, with the error beside the field", async () => {
    const calls = api();
    const host = await mount();
    await openNessus(host);
    await click(host.querySelector('input[value="hash_fields"]')!);
    const alert = host.querySelector("fieldset.ds-match-fields [role=alert]")!;
    expect(alert.textContent).toBe("Choose at least one field to hash.");
    expect(byText(host, "Preview the change").disabled).toBe(true);
    await click(host.querySelector('.ds-match-fields input[type="checkbox"]')!);
    expect(byText(host, "Preview the change").disabled).toBe(false);
    await click(byText(host, "Preview the change"));
    await flush();
    expect(calls.find((c) => c.path.endsWith("/preview"))!.body).toEqual(
      { source: "nessus", strategy: "hash_fields", fields: ["title"] });
    expect(await violations(host)).toEqual([]);
  });

  it("explains a 409 as 'preview again' and clears the stale preview", async () => {
    api({ apply: () => json({ detail: "the project changed since the preview; preview the change again" }, 409) });
    const host = await mount();
    await previewTo(host);
    await click(byText(host, "Apply this change"));
    await flush();
    expect(host.querySelector(".ds-match-error")?.textContent).toContain("Preview the change again");
    expect(host.querySelector(".ds-match-preview")).toBeNull();
  });

  it("will not apply a change that would change nothing, or one with key conflicts", async () => {
    api({ preview: preview({ changes_anything: false, summary: "Switching nessus to tool_id would merge 0 issues into 0 and split none" }) });
    let host = await mount();
    await previewTo(host);
    expect(byText(host, "Apply this change").disabled).toBe(true);
    expect(host.textContent).toContain("This would change nothing.");
    await act(async () => root?.unmount());

    api({ preview: preview({ conflicts: ["dd1:tool_id:abc"] }) });
    host = await mount();
    await previewTo(host);
    expect(host.querySelector(".ds-match-preview [role=alert]")?.textContent).toContain("cannot be applied");
    expect(byText(host, "Apply this change").disabled).toBe(true);
  });

  it("warns when a merge would reopen triage, and when other tools' Issues are left alone", async () => {
    api({ preview: preview({ triage_conflicts: 2, skipped_multi_source: 5 }) });
    const host = await mount();
    await previewTo(host);
    expect(host.querySelector(".ds-match-warn")?.textContent).toContain("2 merges would combine Issues with different triage");
    expect(host.textContent).toContain("Left alone (another tool also reported them)");
  });

  it("lists the history of changes in a real table", async () => {
    api();
    const host = await mount();
    const details = host.querySelector("details")!;
    await act(async () => { details.open = true; details.dispatchEvent(new Event("toggle", { bubbles: true })); });
    await flush();
    const row = host.querySelector(".ds-match-history tbody tr")!;
    expect(row.textContent).toContain("zap");
    expect(row.textContent).toContain("stable ids");
    expect(row.textContent).toContain("3 merged, 0 split off");
    expect(await violations(host)).toEqual([]);
  });

  it("with a preview open, has no accessibility violations", async () => {
    api();
    const host = await mount();
    await previewTo(host);
    expect(await violations(host)).toEqual([]);
  });
});
