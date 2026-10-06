// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DashboardScreen, pickDashboard } from "../components/dashboard/DashboardScreen";
import { MetricIssuesScreen } from "../components/dashboard/MetricIssuesScreen";
import { MetricWidget } from "../components/dashboard/MetricWidget";
import { chartSummary } from "../components/dashboard/charts";
import { CATALOGUE, type Dashboard, type DashboardList, type MetricResult } from "../lib/dashboard";
import { present } from "../lib/dashboard-present";

const replace = vi.fn();
vi.mock("next/navigation", () => ({ usePathname: () => "/app/dashboards", useRouter: () => ({ push: vi.fn(), replace }) }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const AXE = { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } };
const PROJECT = "11111111-1111-4111-8111-111111111111";

function result(metric: string, over: Partial<MetricResult> = {}): MetricResult {
  const base = { metric, name: metric, definition: `How ${metric} is defined.`, unit: "count", generated_at: "2026-10-06T12:00:00Z",
    pending_refresh: 0, notes: [], value: 0, counts: {} };
  const by: Record<string, Partial<MetricResult>> = {
    open_issues: { value: 31, counts: { open: 31 }, rows: [
      { key: "P1", label: "P1", count: 9, score: 537, drill: { kind: "open", band: "P1" } },
      { key: "P2", label: "P2", count: 22, score: 316, drill: { kind: "open", band: "P2" } }] },
    sla_adherence: { value: 0.9112, counts: { met: 195, missed: 7, open_past_deadline: 12, due: 214, exempt: 3 },
      rows: [{ key: "HIGH", met: 195, due: 214, rate: 0.9112 }],
      series: [{ week: "2026-09-28", met: 20, due: 22, rate: 0.9091 }, { week: "2026-10-05", met: 0, due: 0, rate: null }],
      period: ["2026-07-09", "2026-10-06"] },
    mttr: { value: 12.5, counts: { fixed: 4 }, rows: [{ key: "P1", fixed: 4, days: 12.5, drill: { kind: "fixed", band: "P1" } }], period: ["2026-07-09", "2026-10-06"] },
    new_vs_fixed: { value: 3, counts: { new: 5, fixed: 2 }, series: [{ week: "2026-09-28", new: 5, fixed: 2 }],
      drill: { new: { kind: "opened" }, fixed: { kind: "fixed" } }, period: ["2026-07-09", "2026-10-06"] },
    open_risk: { value: 853, counts: { open: 31 }, rows: [{ key: "P1", label: "P1", count: 9, score: 537, drill: { kind: "open", band: "P1" } }],
      series: [{ week: "2026-09-28", risk: 800 }, { week: "2026-10-05", risk: 853 }], period: ["2026-07-09", "2026-10-06"] },
    backlog_age: { value: 40, counts: { open: 31, over_30: 20, over_90: 5, over_180: 1 }, rows: [
      { key: "over_30", count: 20, drill: { kind: "open", older_than: 30 } }] },
    past_sla: { value: 12, counts: { past_sla: 12 }, rows: [{ issue_id: "i1", project_id: PROJECT, project: "acme/api", portfolio: "Payments",
      title: "SQL injection", band: "P1", severity: "HIGH", days_over: 9, assignee: "token:abc", assignee_name: "Priya N." }] },
    scan_coverage: { value: 6 / 7, counts: { scanned_recently: 6, projects: 7 }, rows: [{ project_id: PROJECT, project: "acme/api",
      days_since: 0, scanners_ok: 6, scanners_applicable: 7 }], days: 30 },
  };
  return { ...base, ...(by[metric] ?? {}) } as MetricResult;
}

const DASH: Dashboard = {
  id: "d1", name: "Program", owner: "token:me", shared_with: ["lead"], version: 3, updated_at: null, updated_by: null,
  builtin: false, can_edit: true,
  widgets: [
    { id: "sla", metric: "sla_adherence", x: 0, y: 0, w: 6, h: 4, filters: {} },
    { id: "open", metric: "open_issues", x: 6, y: 0, w: 6, h: 4, filters: { tag: "pci" } },
  ],
};
const BUILTIN: Dashboard = { ...DASH, id: "builtin:program", name: "Program overview", owner: null, builtin: true, can_edit: false, version: 0 };

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
type Call = { method: string; path: string; search: string; body?: unknown };

function api(o: { list?: DashboardList; put?: (b: unknown) => Response } = {}) {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ method, path: u.pathname, search: u.search, body });
    if (u.pathname === "/v2/dashboards" && method === "GET") return json(o.list ?? { role: "lead", dashboards: [DASH, BUILTIN] });
    if (u.pathname === "/v2/dashboards/d1" && method === "PUT") {
      return o.put ? o.put(body) : json({ ...DASH, ...(body as object), version: 4 });
    }
    if (u.pathname === "/v2/metrics") return json(CATALOGUE.map((e) => ({ id: e.metric, name: e.title, definition: `Def of ${e.metric}`, unit: "count", period: e.periodic })));
    if (u.pathname.startsWith("/v2/metrics/issues")) {
      return json({ rows: Array.from({ length: 2 }, (_, i) => ({ id: `i${i}`, project_id: PROJECT, project: "acme/api", title: `Issue ${i}`,
        severity: "HIGH", band: "P1", state: "open", first_seen_at: "2026-09-01T00:00:00Z", fixed_at: null, assignee: null, assignee_name: null })), next: "i1" });
    }
    if (u.pathname.startsWith("/v2/metrics/")) return json(result(u.pathname.split("/").pop()!));
    if (u.pathname === "/v2/portfolios" || u.pathname === "/assets") return json([]);
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
  await flush(60);
  return host;
}
const button = (scope: ParentNode, label: string) =>
  Array.from(scope.querySelectorAll("button")).find((b) => (b.getAttribute("aria-label") ?? b.textContent ?? "").trim().startsWith(label)) as HTMLButtonElement;
const live = () => document.querySelector('[aria-live="polite"].sr-only')!.textContent;

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  vi.stubGlobal("matchMedia", (q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {} }));
});
afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
  replace.mockReset();
});

describe("what each widget shows", () => {
  it("never shows a percentage without its counts, and every chart has a table", () => {
    for (const e of CATALOGUE) {
      const p = present(result(e.metric));
      if (e.chart && p.charts.length) expect(p.tables.length).toBeGreaterThan(0);
      const words = [p.headline.text, ...p.detail.map((d) => d.text), ...p.tables.flatMap((t) => t.rows.flat().map((c) => c.text))].join(" ");
      for (const pct of words.match(/\d+%[^,.;]*/g) ?? []) expect(pct).toMatch(/^\d+% \([\d,]+ of [\d,]+\)/);
    }
    expect(present(result("sla_adherence")).headline.text).toBe("91% (195 of 214) fixed within SLA");
    expect(present(result("scan_coverage")).tables[0]!.rows[0]![2]!.text).toBe("6 of 7");
  });
  it("links every count of Issues to those Issues, with the widget's filters and the count", () => {
    const open = present(result("open_issues"), { tag: "pci" });
    expect(open.headline.href).toBe("/app/metrics/issues?tag=pci&kind=open&label=Open+issues&n=31");
    expect(open.tables[0]!.rows[0]![1]!.href).toBe("/app/metrics/issues?tag=pci&kind=open&band=P1&label=Open+issues%2C+P1&n=9");
    const sla = present(result("sla_adherence"));
    expect(sla.detail[1]!.href).toContain("kind=past_sla");
    expect(sla.detail[1]!.href).toContain("&n=12&from=2026-07-09&to=2026-10-06");
    const past = present(result("past_sla"));
    expect(past.tables[0]!.rows[0]![1]!.href).toBe(`/app/projects/${PROJECT}/issues/i1`);
    expect(past.tables[0]!.rows[0]![4]!.text).toBe("Priya N.");
  });
  it("summarises charts in words for screen readers", () => {
    const p = present(result("sla_adherence"));
    expect(chartSummary(p.charts[0]!)).toBe("Share fixed within SLA, by week: 91% in the week of 2026-09-28, 91% in the week of 2026-09-28; highest 91%, lowest 91%.");
    expect(chartSummary(present(result("new_vs_fixed")).charts[0]!)).toBe("New and fixed issues by week, over 1 weeks: 5 new, 2 fixed in all.");
  });
});

describe("a widget", () => {
  it("opens its definition from its title, reads as a table, and has no accessibility violations", async () => {
    api();
    const host = await mount(<MetricWidget widget={{ id: "w", metric: "open_issues", x: 0, y: 0, w: 6, h: 4, filters: { tag: "pci" } }} />);
    expect(host.querySelector(".dash-headline a")!.textContent).toBe("31 open issues");
    expect(host.querySelector(".dash-filters")!.textContent).toBe("tag “pci”");
    expect(host.querySelectorAll(".dash-bars a").length).toBe(2);
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    const toggle = button(host, "View as table: Open issues by priority");
    await act(async () => toggle.click());
    expect(toggle.getAttribute("aria-pressed")).toBe("true");
    expect(host.querySelector("table caption")!.textContent).toBe("Open issues by priority");
    expect(host.querySelector("tbody tr th")!.getAttribute("scope")).toBe("row");
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    await act(async () => button(host, "Open issues by priority: what this measures").click());
    const dialog = document.querySelector("[role=dialog]")!;
    expect(dialog.textContent).toContain("How open_issues is defined.");
    expect((await axe.run(dialog as HTMLElement, AXE)).violations).toEqual([]);
    await act(async () => button(dialog, "Close").click());
    expect(document.querySelector("[role=dialog]")).toBeNull();
  });
});

describe("the dashboard screen", () => {
  it("opens your own dashboard first, else one shared with your role, else the built-in one", () => {
    const shared = { ...DASH, id: "s", can_edit: false, owner: "token:x" };
    expect(pickDashboard({ role: "lead", dashboards: [shared, DASH, BUILTIN] })!.id).toBe("d1");
    expect(pickDashboard({ role: "lead", dashboards: [shared, BUILTIN] })!.id).toBe("s");
    expect(pickDashboard({ role: "tester", dashboards: [shared, BUILTIN] })!.id).toBe("builtin:program");
    expect(pickDashboard({ role: null, dashboards: [DASH, BUILTIN] }, "builtin:program")!.id).toBe("builtin:program");
  });

  it("moves and resizes with the keyboard, announces each change, and saves the layout", async () => {
    const calls = api();
    const host = await mount(<DashboardScreen />);
    expect(host.querySelector("h1")!.textContent).toBe("Program");
    expect(replace).toHaveBeenCalledWith("/app/dashboards?d=d1", { scroll: false });
    await act(async () => button(host, "Edit").click());
    await flush();
    const handle = button(host, "Move SLA adherence");
    expect(document.getElementById(handle.getAttribute("aria-describedby")!)!.textContent).toMatch(/arrow keys to move it and Shift/);
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    handle.focus();
    const key = (k: string, shiftKey = false) => act(async () => { handle.dispatchEvent(new KeyboardEvent("keydown", { key: k, shiftKey, bubbles: true })); });
    await key("ArrowDown");
    expect(live()).toBe("SLA adherence can't go further that way. It is at column 1 of 12, row 1, 6 columns wide, 4 rows tall.");
    await key("ArrowRight");
    expect(live()).toBe("SLA adherence moved to column 2 of 12, row 1, 6 columns wide, 4 rows tall.");
    await key("ArrowDown", true);
    expect(live()).toBe("SLA adherence resized to 6 columns wide, 5 rows tall, at column 2 of 12, row 1.");
    expect(document.activeElement).toBe(handle);
    await act(async () => button(host, "Save").click());
    await flush();
    const put = calls.find((c) => c.method === "PUT")!;
    expect(put.body).toMatchObject({ version: 3, name: "Program", shared_with: ["lead"] });
    const saved = (put.body as { widgets: { id: string; x: number; y: number; w: number; h: number }[] }).widgets;
    expect(saved.find((w) => w.id === "sla")).toMatchObject({ x: 1, y: 0, w: 6, h: 5 });
    expect(saved.find((w) => w.id === "open")!.y).toBeGreaterThanOrEqual(5); // made room
    expect(host.querySelector(".dash-notice")!.textContent).toBe("Saved “Program”.");
  });

  it("refuses a stale save and offers the saved version", async () => {
    api({ put: () => json({ detail: { field: "version", message: "Someone saved this dashboard since you opened it (now version 4). Reload it, then make your change again." } }, 409) });
    const host = await mount(<DashboardScreen />);
    await act(async () => button(host, "Edit").click());
    await act(async () => button(host, "Save").click());
    await flush();
    expect(host.querySelector("[role=alert]")!.textContent).toContain("now version 4");
    expect(button(host, "Reload the saved version")).toBeTruthy();
  });

  it("offers a copy, not an edit, of a dashboard that isn't yours", async () => {
    api({ list: { role: "lead", dashboards: [BUILTIN] } });
    const host = await mount(<DashboardScreen />);
    expect(button(host, "Edit")).toBeUndefined();
    expect(button(host, "Copy to my dashboards")).toBeTruthy();
    expect(host.querySelector(".dash-meta")!.textContent).toBe("Built in · shared with Leads");
  });

  it("adds a widget from the catalogue with its definition", async () => {
    api();
    const host = await mount(<DashboardScreen />);
    await act(async () => button(host, "Edit").click());
    await act(async () => button(host, "Add widget").click());
    await flush();
    const dialog = document.querySelector("[role=dialog]")!;
    expect(dialog.querySelectorAll("li").length).toBe(CATALOGUE.length);
    const add = button(dialog, "Add Past SLA");
    expect(document.getElementById(add.getAttribute("aria-describedby")!)!.textContent).toBe("Def of past_sla");
    await act(async () => add.click());
    await flush();
    expect(live()).toBe("Added Past SLA at row 5.");
    expect(button(host, "Move Past SLA")).toBeTruthy();
  });
});

describe("the Issues behind a number", () => {
  it("lists them with links, and says how many there are in all", async () => {
    api();
    const host = await mount(<MetricIssuesScreen query="kind=open&band=P1&label=Open+issues%2C+P1&n=9" />);
    expect(host.querySelector("h1")!.textContent).toBe("Open issues, P1");
    expect(host.querySelector("caption")!.textContent).toBe("Showing 2 of 9");
    expect(host.querySelector("tbody a")!.getAttribute("href")).toBe(`/app/projects/${PROJECT}/issues/i0`);
    expect((await axe.run(host, AXE)).violations).toEqual([]);
  });
});
