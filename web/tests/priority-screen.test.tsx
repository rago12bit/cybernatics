// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { IssuesTable } from "../components/IssuesTable";
import { PriorityScreen, recomputeSentence } from "../components/PriorityScreen";
import { SlaScreen } from "../components/SlaScreen";
import { WhyRankedPanel } from "../design-system/why-ranked";
import type { Finding, IssuePriority, PriorityOverview, PriorityPreview, PriorityRecompute, SlaOverview } from "../lib/types";
import demo from "../lib/demo-data.json";

vi.mock("next/navigation", () => ({ usePathname: () => "/app", useRouter: () => ({ push: vi.fn() }) }));
// jsdom has no layout, so a real virtualizer draws no rows; this one draws every row.
vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({ count, estimateSize }: { count: number; estimateSize: () => number }) => ({
    getTotalSize: () => count * estimateSize(),
    getVirtualItems: () => Array.from({ length: count }, (_, index) => ({ index, start: index * estimateSize(), size: estimateSize(), key: index })),
  }),
}));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const P = "11111111-1111-4111-8111-111111111111";
const KEYS = ["severity", "epss", "kev", "reachability", "taint", "runtime", "agreement", "path", "assistant", "internet_facing", "data_sensitivity", "criticality"];
const STARTER = Object.fromEntries(KEYS.map((k) => [k, 1]));
const V2 = { ...STARTER, taint: 0, runtime: 0, path: 0 };
const NO_CONTEXT = { internet_facing: null, data_sensitivity: null, criticality: null };

function overview(over: Partial<PriorityOverview> = {}): PriorityOverview {
  return {
    version: 0, weights: V2, context: NO_CONTEXT, starter: STARTER, max_weight: 3,
    factors: KEYS.map((k) => ({ key: k, label: k === "path" ? "Path context" : k.replace(/_/g, " "), description: `About ${k}` })),
    bands: { P1: 80, P2: 60, P3: 30, P4: 0 }, sensitivity_levels: ["public", "internal", "confidential", "restricted"],
    criticality_levels: ["low", "medium", "high", "critical"], locked: false, recompute: null, history: [], ...over,
  };
}

const rc = (over: Partial<PriorityRecompute> = {}): PriorityRecompute =>
  ({ status: "done", total: 10, processed: 10, changed: 3, started_at: null, finished_at: null, error: null, ...over });

const PREVIEW: PriorityPreview = {
  open_issues: 3, current_version: 0, moved: 2,
  top: [
    { issue_id: "b", title: "High in app", severity: "HIGH", path: "app/b.py", before: { rank: 2, score: 56, band: "P3" }, after: { rank: 1, score: 56, band: "P3" } },
    { issue_id: "c", title: "Medium in app", severity: "MEDIUM", path: "app/c.py", before: { rank: 3, score: 40, band: "P3" }, after: { rank: 2, score: 40, band: "P3" } },
  ],
  dropped: [{ issue_id: "a", title: "Critical in tests", severity: "CRITICAL", path: "tests/a.py", before: { rank: 1, score: 90, band: "P1" }, after: { rank: 3, score: 19, band: "P4" } }],
  bands_before: { P1: 1, P2: 0, P3: 2, P4: 0 }, bands_after: { P1: 0, P2: 0, P3: 2, P4: 1 },
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
type Call = { method: string; path: string; search: string; body?: unknown };

function api(o: { get?: () => PriorityOverview; put?: (b: unknown) => Response; preview?: (b: unknown) => Response; issues?: Finding[]; sla?: SlaOverview } = {}) {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ method, path: u.pathname, search: u.search, body });
    if (u.pathname.endsWith("/priority/preview")) return o.preview ? o.preview(body) : json(PREVIEW);
    if (u.pathname.endsWith("/priority") && method === "PUT")
      return o.put ? o.put(body) : json(overview({ version: 1, weights: (body as { weights: Record<string, number> }).weights, locked: true, recompute: rc({ status: "running", processed: 4 }) }), 202);
    if (u.pathname.endsWith("/priority")) return json(o.get ? o.get() : overview());
    if (u.pathname.endsWith("/sla")) return json(o.sla);
    if (u.pathname.endsWith("/issues")) return json({ total: o.issues?.length ?? 0, limit: 200, offset: 0, items: o.issues ?? [] });
    return json({}, 404);
  }));
  return calls;
}

let root: Root | null = null;
const flush = (ms = 40) => act(async () => { await new Promise((r) => setTimeout(r, ms)); });
async function mount(el: React.ReactElement) {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(el));
  await flush();
  return host;
}
const button = (host: HTMLElement, text: string) =>
  Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.trim().startsWith(text)) as HTMLButtonElement;
const labelled = (host: HTMLElement, text: string) => {
  const label = Array.from(host.querySelectorAll("label")).find((l) => l.textContent?.startsWith(text))!;
  return document.getElementById(label.htmlFor) as HTMLInputElement & HTMLSelectElement;
};
async function setValue(el: HTMLInputElement | HTMLSelectElement, value: string) {
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(el, value);
  await act(async () => el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? "change" : "input", { bubbles: true })));
}

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  vi.useRealTimers();
  document.body.innerHTML = "";
});

describe("PriorityScreen", () => {
  it("describes the recomputation in words", () => {
    expect(recomputeSentence(rc({ status: "running", processed: 340, total: 1204 }))).toBe("Applying the new weights: 340 of 1,204 issues…");
    expect(recomputeSentence(rc())).toBe("Applied to 10 issues; 3 changed band.");
    expect(recomputeSentence(rc({ status: "failed", error: "disk full" }))).toContain("disk full");
    expect(recomputeSentence(null)).toBeNull();
  });

  it("starts from the standard score and only saves after a preview of the same weights", async () => {
    const calls = api();
    const host = await mount(<PriorityScreen assetId={P} />);
    expect(host.querySelector(".ds-prio-verdict")!.textContent).toContain("standard risk score");
    expect(labelled(host, "Path context").value).toBe("0");
    expect(host.textContent).toContain("Off");
    await setValue(labelled(host, "Path context"), "2");
    expect(labelled(host, "Path context").getAttribute("aria-valuetext")).toBe("×2");
    await setValue(labelled(host, "Business criticality"), "critical");
    await setValue(labelled(host, "Internet-facing"), "yes");
    expect(button(host, "Save and re-rank")).toBeUndefined(); // no preview yet
    await act(async () => button(host, "Preview the top 50").click());
    await flush();
    const pv = calls.find((c) => c.path.endsWith("/preview"))!;
    expect(pv.body).toMatchObject({ weights: { path: 2, severity: 1 }, context: { criticality: "critical", internet_facing: true, data_sensitivity: null } });
    expect(host.textContent).toContain("2 of the top 2 move under these weights, and 1 leave it.");
    const rows = Array.from(host.querySelectorAll(".ds-prio-top tbody tr")).map((r) => r.textContent);
    expect(rows[0]).toContain("▲ 1 (was 2)");
    expect(host.querySelector(".ds-prio-dropped")!.textContent).toContain("Critical in tests: rank 1 → 3, score 90 → 19");
    expect(host.querySelector(".ds-prio-bands")!.textContent).toContain("P110");
    // a change after the preview needs another preview
    await setValue(labelled(host, "Path context"), "3");
    expect(button(host, "Save and re-rank").disabled).toBe(true);
    expect(host.textContent).toContain("Preview again before saving");
    await act(async () => button(host, "Preview the top 50").click());
    await flush();
    await setValue(host.querySelector(".ds-prio-row input") as HTMLInputElement, "Payments service");
    await act(async () => button(host, "Save and re-rank").click());
    await flush();
    const put = calls.find((c) => c.method === "PUT")!;
    expect(put.path).toBe(`/v2/projects/${P}/priority`);
    expect(put.body).toMatchObject({ weights: { path: 3 }, note: "Payments service", context: { criticality: "critical" } });
    expect(host.querySelector('[role="status"].ds-prio-status')!.textContent).toContain("4 of 10 issues");
  });

  it("follows a running recomputation until it finishes", async () => {
    let n = 0;
    api({ get: () => (++n < 2 ? overview({ version: 2, weights: STARTER, locked: true, recompute: rc({ status: "running", processed: 2 }) })
      : overview({ version: 2, weights: STARTER, recompute: rc() })) });
    const host = await mount(<PriorityScreen assetId={P} />);
    expect(host.querySelector(".ds-prio-status")!.textContent).toContain("2 of 10");
    expect(host.querySelector("progress")).not.toBeNull();
    await flush(1700);
    expect(host.querySelector(".ds-prio-status")!.textContent).toBe("Applied to 10 issues; 3 changed band.");
    expect(host.querySelector("progress")).toBeNull();
  });

  it("says the save was refused while the last change is applied", async () => {
    api({
      get: () => overview({ version: 1, weights: STARTER }),
      put: () => json({ detail: { code: "PRIORITY_RECOMPUTING", message: "The last change is still being applied to every issue. Try again when it finishes." } }, 409),
    });
    const host = await mount(<PriorityScreen assetId={P} />);
    await setValue(labelled(host, "severity"), "2");
    await act(async () => button(host, "Preview the top 50").click());
    await flush();
    await act(async () => button(host, "Save and re-rank").click());
    await flush();
    expect(host.querySelector('[role="alert"]')!.textContent).toContain("still being applied");
  });

  it("puts a server field error on the field", async () => {
    api({ preview: () => json({ detail: { field: "weights.kev", message: "kev: the weight is 0 to 3" } }, 422) });
    const host = await mount(<PriorityScreen assetId={P} />);
    await act(async () => button(host, "Preview the top 50").click());
    await flush();
    const el = labelled(host, "kev");
    expect(el.getAttribute("aria-invalid")).toBe("true");
    expect(document.getElementById(el.getAttribute("aria-describedby")!.split(" ")[0]!)!.textContent).toBe("kev: the weight is 0 to 3");
  });

  it("lists what each version changed", async () => {
    api({ get: () => overview({ version: 1, weights: { ...STARTER, path: 2 }, context: { ...NO_CONTEXT, criticality: "high" }, recompute: rc(),
      history: [{ version: 1, weights: { ...STARTER, path: 2 }, context: { ...NO_CONTEXT, criticality: "high" }, note: "tests are noise", changed_at: "2026-10-05T09:00:00Z", changed_by: "Alice", recompute: rc() }] }) });
    const host = await mount(<PriorityScreen assetId={P} />);
    expect(host.querySelector(".ds-prio-verdict")!.textContent).toContain("version 1, saved by Alice");
    const h = host.querySelector(".ds-prio-history")!.textContent!;
    expect(h).toContain("Path context ×2, high criticality");
    expect(h).toContain("10 issues");
  });

  it("has no accessibility violations, with a preview open", async () => {
    api();
    const host = await mount(<PriorityScreen assetId={P} />);
    await act(async () => button(host, "Preview the top 50").click());
    await flush();
    const r = await axe.run(host, { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } });
    expect(r.violations.map((v) => v.id)).toEqual([]);
  });
});

describe("priority on issues", () => {
  const base = (demo.findings as unknown as Finding[])[0]!;
  const withPriority = (id: string, title: string, priority: IssuePriority | null): Finding =>
    ({ ...base, id, title, issue: { id: `i-${id}`, state: "open", triage_status: "open", priority } });

  it("shows the band and score, and filters by band", async () => {
    const calls = api({ issues: [
      withPriority("a", "Top one", { score: 92, band: "P1", version: 1, factors: [{ text: "Critical severity", factor: "severity", weight: 1, effect: 0.95 }] }),
      withPriority("b", "Unranked", null),
    ] });
    const host = await mount(<IssuesTable assetId={P} />);
    const cells = Array.from(host.querySelectorAll(".ds-issues-cell.col-priority")).map((c) => c.textContent?.trim());
    expect(cells).toEqual(["P1 92", ""]);
    expect(host.querySelector(".ds-issue-prio-P1")!.getAttribute("title")).toBe("Critical severity");
    await act(async () => button(host, "P1").click());
    await flush();
    const last = calls.filter((c) => c.path.endsWith("/issues")).at(-1)!;
    expect(new URLSearchParams(last.search).getAll("priority")).toEqual(["P1"]);
    expect(button(host, "P1").getAttribute("aria-pressed")).toBe("true");
  });

  it("explains a rank with each factor's weight", async () => {
    const host = await mount(
      <WhyRankedPanel factors={["v2 reason"]} riskScore={72} band="P2"
        weighted={[{ text: "High severity", factor: "severity", weight: 1, effect: 0.75 },
          { text: "In CISA KEV: exploited in the wild: at least 90", factor: "kev", weight: 1, effect: 90 },
          { text: "In test code", factor: "path", weight: 1.5, effect: 0.465 }]} />,
    );
    const text = host.textContent!;
    expect(text).toContain("P2 · 72");
    expect(text).toContain("High severity (weight 1 · ×0.75)");
    expect(text).toContain("at least 90 (weight 1)");
    expect(text).toContain("In test code (weight 1.5 · ×0.47)");
    expect(text).not.toContain("v2 reason");
  });

  it("lets an SLA key on priority bands", async () => {
    const STARTER_SEV = { CRITICAL: { days: 7, warn: 2 }, HIGH: { days: 30, warn: 7 }, MEDIUM: { days: 90, warn: 14 }, LOW: { days: 180, warn: 30 }, INFO: { days: null, warn: 0 } };
    const BY_P = { P1: { days: 7, warn: 2 }, P2: { days: 30, warn: 7 }, P3: { days: 90, warn: 14 }, P4: { days: 180, warn: 30 } };
    const sla: SlaOverview = { enabled: false, basis: "severity", version: 0, bands: STARTER_SEV, starter: STARTER_SEV, starter_by_priority: BY_P,
      counts: { on_track: 0, due_soon: 0, breached: 0, exempt: 0, met: 0, missed: 0 }, history: [] };
    const calls: Call[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      const u = new URL(String(url));
      const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
      calls.push({ method: init?.method ?? "GET", path: u.pathname, search: u.search, body });
      return init?.method === "PUT" ? json({ ...sla, enabled: true, basis: "priority", version: 1, bands: BY_P }) : json(sla);
    }));
    const host = await mount(<SlaScreen assetId={P} />);
    const radio = Array.from(host.querySelectorAll('.ds-sla-basis input[type="radio"]')) as HTMLInputElement[];
    await act(async () => radio[1]!.click());
    expect((host.querySelector('input[aria-label="p1: fix within, days"]') as HTMLInputElement).value).toBe("7");
    expect(host.querySelector('input[aria-label="critical: fix within, days"]')).toBeNull();
    expect(host.textContent).toContain("priority weights");
    await act(async () => button(host, "Save policy").click());
    await flush();
    const put = calls.find((c) => c.method === "PUT")!;
    expect(put.body).toMatchObject({ basis: "priority", bands: { P1: { days: 7, warn: 2 }, P4: { days: 180, warn: 30 } } });
    expect((Array.from(host.querySelectorAll('.ds-sla-basis input[type="radio"]'))[1] as HTMLInputElement).checked).toBe(true);
  });
});
