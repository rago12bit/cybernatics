// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { IssuesTable } from "../components/IssuesTable";
import { SlaScreen, slaVerdict } from "../components/SlaScreen";
import { slaDetail, slaSentence } from "../lib/sla";
import type { Finding, IssueSla, SlaOverview } from "../lib/types";
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
const STARTER = { CRITICAL: { days: 7, warn: 2 }, HIGH: { days: 30, warn: 7 }, MEDIUM: { days: 90, warn: 14 },
  LOW: { days: 180, warn: 30 }, INFO: { days: null, warn: 0 } };
const ZERO = { on_track: 0, due_soon: 0, breached: 0, exempt: 0, met: 0, missed: 0 };

function overview(over: Partial<SlaOverview> = {}): SlaOverview {
  return { enabled: false, basis: "severity", version: 0, bands: STARTER, starter: STARTER, counts: ZERO, history: [], ...over };
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
type Call = { method: string; path: string; search: string; body?: unknown };

function api(o: { sla?: SlaOverview; put?: (b: unknown) => Response; issues?: Finding[] } = {}) {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ method, path: u.pathname, search: u.search, body });
    if (u.pathname.endsWith("/sla") && method === "PUT") return o.put ? o.put(body) : json(overview({ enabled: true, version: 1 }));
    if (u.pathname.endsWith("/sla")) return json(o.sla ?? overview());
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
async function type(el: HTMLInputElement, value: string) {
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(el, value);
  await act(async () => el.dispatchEvent(new Event("input", { bubbles: true })));
}
const input = (host: HTMLElement, label: string) => host.querySelector(`input[aria-label="${label}"]`) as HTMLInputElement;

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("SLA wording", () => {
  const now = new Date("2026-10-05T12:00:00Z").getTime();
  const sla = (state: IssueSla["state"], due: string): IssueSla => ({ state, due_at: due, started_at: null, days: 30 });
  it("says the state in words and the days left or overdue", () => {
    expect(slaSentence(sla("breached", "2026-10-02T12:00:00Z"), now)).toBe("Breached · 3 days overdue");
    expect(slaSentence(sla("due_soon", "2026-10-07T13:00:00Z"), now)).toBe("Due soon · 2 days left");
    expect(slaSentence(sla("due_soon", "2026-10-05T18:00:00Z"), now)).toBe("Due soon · due today");
    expect(slaSentence(sla("breached", "2026-10-05T06:00:00Z"), now)).toBe("Breached · overdue today");
    expect(slaSentence(undefined)).toBe("No SLA");
    expect(slaDetail({ state: "none", due_at: null, started_at: null, days: null })).toBe("");
  });
});

describe("SlaScreen", () => {
  it("opens with a verdict", () => {
    expect(slaVerdict(overview())).toBe("No SLA yet. The starter values below are a suggestion.");
    expect(slaVerdict(overview({ enabled: true, version: 2 }))).toBe("Every open issue is on track.");
    expect(slaVerdict(overview({ enabled: true, version: 2, counts: { ...ZERO, breached: 2, due_soon: 1 } }))).toBe("2 breached, 1 due soon.");
    expect(slaVerdict(overview({ enabled: false, version: 3 }))).toBe("The SLA is turned off.");
  });

  it("offers the starter values, and saves the edited policy with why", async () => {
    const calls = api();
    const host = await mount(<SlaScreen assetId={P} />);
    expect(input(host, "high: fix within, days").value).toBe("30");
    expect(input(host, "info: fix within, days").value).toBe("");
    expect(input(host, "info: due soon in the last, days").disabled).toBe(true);
    expect((host.querySelector(".ds-sla-toggle input") as HTMLInputElement).checked).toBe(true);
    await type(input(host, "high: fix within, days"), "14");
    await type(input(host, "high: due soon in the last, days"), "3");
    await type(host.querySelector(".ds-sla-row input") as HTMLInputElement, "Audit finding");
    await act(async () => button(host, "Save policy").click());
    await flush();
    const put = calls.find((c) => c.method === "PUT")!;
    expect(put.path).toBe(`/v2/projects/${P}/sla`);
    expect(put.body).toMatchObject({ enabled: true, note: "Audit finding",
      bands: { HIGH: { days: 14, warn: 3 }, CRITICAL: { days: 7, warn: 2 }, INFO: { days: null, warn: 0 } } });
    expect(host.textContent).toContain("Saved as version 1.");
  });

  it("shows counts and history once there is a policy", async () => {
    api({ sla: overview({ enabled: true, version: 2, counts: { ...ZERO, breached: 3, due_soon: 1, on_track: 9 },
      history: [{ version: 2, enabled: true, bands: STARTER, note: "tighter", changed_at: "2026-10-05T09:00:00Z", changed_by: "token:abc" }] }) });
    const host = await mount(<SlaScreen assetId={P} />);
    expect(host.querySelector(".ds-sla-verdict")!.textContent).toBe("3 breached, 1 due soon.");
    const counts = host.querySelector(".ds-sla-counts")!.textContent!;
    expect(counts).toContain("Breached3");
    expect(counts).toContain("On track9");
    expect(host.querySelector(".ds-sla-history")!.textContent).toContain("Critical 7d, High 30d");
  });

  it("puts a server field error on the field", async () => {
    api({ put: () => json({ detail: { field: "bands.HIGH.warn", message: "High: the warning is 0 to 29 days before the deadline" } }, 422) });
    const host = await mount(<SlaScreen assetId={P} />);
    await type(input(host, "high: due soon in the last, days"), "40");
    await act(async () => button(host, "Save policy").click());
    await flush();
    const el = input(host, "high: due soon in the last, days");
    expect(el.getAttribute("aria-invalid")).toBe("true");
    expect(document.getElementById(el.getAttribute("aria-describedby")!)!.textContent).toContain("0 to 29 days");
  });

  it("has no accessibility violations", async () => {
    api({ sla: overview({ enabled: true, version: 1, counts: { ...ZERO, breached: 1 } }) });
    const host = await mount(<SlaScreen assetId={P} />);
    const r = await axe.run(host, { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } });
    expect(r.violations.map((v) => v.id)).toEqual([]);
  });
});

describe("the issues table's SLA", () => {
  const base = (demo.findings as unknown as Finding[])[0]!;
  const withSla = (id: string, title: string, sla: IssueSla): Finding =>
    ({ ...base, id, title, issue: { id: `i-${id}`, state: "open", triage_status: "open", sla } });
  const soon = new Date(Date.now() + 2.5 * 86_400_000).toISOString();
  const late = new Date(Date.now() - 3.5 * 86_400_000).toISOString();

  it("shows each issue's SLA as a word, and filters by it", async () => {
    const calls = api({ issues: [
      withSla("a", "Breached one", { state: "breached", due_at: late, started_at: null, days: 30 }),
      withSla("b", "Soon one", { state: "due_soon", due_at: soon, started_at: null, days: 30 }),
      withSla("c", "No-SLA one", { state: "none", due_at: null, started_at: null, days: null }),
    ] });
    const host = await mount(<IssuesTable assetId={P} />);
    const cells = Array.from(host.querySelectorAll(".ds-issues-cell.col-sla")).map((c) => c.textContent?.trim());
    expect(cells).toEqual(["▲ Breached · 3 days overdue", "◐ Due soon · 2 days left", ""]);
    await act(async () => button(host, "▲ Breached").click());
    await flush();
    const last = calls.filter((c) => c.path.endsWith("/issues")).at(-1)!;
    expect(new URLSearchParams(last.search).getAll("sla")).toEqual(["breached"]);
    expect(button(host, "▲ Breached").getAttribute("aria-pressed")).toBe("true");
  });
});
