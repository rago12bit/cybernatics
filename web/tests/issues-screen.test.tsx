// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { IssuesScreen } from "../components/issues/IssuesScreen";
import { parse, formatQuery } from "../lib/issue-query";
import { LEGACY_DONE, activeCount, chipsOf, legacyToQuery, readLegacyViews, toggled, type IssueRow, type SavedView } from "../lib/issues";

vi.mock("next/navigation", () => ({ usePathname: () => "/app/issues", useRouter: () => ({ push: vi.fn(), replace: vi.fn() }) }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const AXE = { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

function row(i: number, over: Partial<IssueRow> = {}): IssueRow {
  return {
    id: `i${i}`, project_id: "p1", project: "acme/payments-api", title: `Issue number ${i}`, severity: "high", band: "P1", score: 90 - i,
    status: "open", state: "open", accepted_until: null, sla: { state: "breached", due_at: null }, assignee: null, assignee_name: null,
    path: `src/m${i}.py`, category: "sast", source: "scanner", retest: null, first_seen_at: "2026-09-01T00:00:00Z",
    last_seen_at: "2026-10-06T00:00:00Z", fixed_at: null, ...over,
  };
}
const VIEWS: SavedView[] = [
  { id: "v1", name: "Payments P1", owner: "token:me", query: "priority:P1 project:payments-*", sort: "newest", columns: ["project", "path"],
    shared_with: [], version: 1, updated_at: null, updated_by: null, builtin: false, can_edit: true },
  { id: "builtin:mine", name: "Assigned to me", owner: null, query: "assignee:me", sort: "priority", columns: null,
    shared_with: ["lead", "engineer", "tester"], version: 0, updated_at: null, updated_by: null, builtin: true, can_edit: false },
];

type Call = { method: string; path: string; params: URLSearchParams; body?: unknown };
function api(o: { total?: number } = {}) {
  const calls: Call[] = [];
  const total = o.total ?? 1204;
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ method, path: u.pathname, params: u.searchParams, body });
    const p = u.pathname;
    if (p === "/v2/issues") {
      const after = u.searchParams.get("after");
      const base = after ? 50 : 0;
      return json({ rows: Array.from({ length: 50 }, (_, i) => row(base + i)), next: after ? null : "c1",
        count: after ? null : { value: total, exact: true }, sort: u.searchParams.get("sort"), query: u.searchParams.get("q") });
    }
    if (p === "/v2/issue-views" && method === "POST") return json({ ...VIEWS[0], id: "v9", name: (body as { name: string }).name }, 201);
    if (p === "/v2/issue-views") return json(VIEWS);
    if (p === "/v2/me") return json({ actor: "token:me", person: true, role: "lead", roles: ["lead", "engineer", "tester"] });
    if (p === "/v2/me/tables/issues" && method === "PUT") return json({ ...(body as object), density: (body as { density: string }).density, saved: true });
    if (p === "/v2/me/tables/issues") return json({ columns: ["project", "priority", "severity", "status", "sla", "assignee", "first_seen"], density: "comfortable", saved: false });
    if (p === "/v2/issues/suggest") return json({ key: u.searchParams.get("key"), values: ["acme/payments-api"] });
    if (p === "/v2/issues/bulk/preview" && (body as { action: string }).action === "accept") return json({ action: "accept", selected: 3,
      will_change: 3, unchanged: 0, skipped: [{ reason: "under a risk acceptance: decide it there", count: 1 }], by_project: [], by_severity: {},
      expected_count: 4, reversible: false, sentence: "3 Issues in 2 projects can be put forward for risk acceptance: one request per project, which a second person approves.",
      flow: { kind: "risk_acceptance", projects: [
        { project_id: "p1", project: "acme/payments-api", count: 2, issue_ids: ["i1", "i2"], truncated: false },
        { project_id: "p2", project: "acme/ledger", count: 1, issue_ids: ["i3"], truncated: false }] } });
    if (p === "/v2/risk-acceptance-policy") return json({ max_days: 365, you: "token:me", approvers: [{ actor: "token:b", name: "Bob" }], can_approve: true });
    if (p === "/v2/issues/bulk/preview") return json({ action: "assign", selected: total, will_change: 1200, unchanged: 4, skipped: [],
      by_project: [{ project: "acme/payments-api", count: 1200 }], by_severity: { high: 1200 }, expected_count: total, reversible: true,
      sentence: "Assign to Priya N.: 1,200 Issues will change. 4 Issues already are as asked." });
    if (p === "/v2/issues/bulk") return json({ batch_id: "b1", action: "assign", changed: 1200, unchanged: 4, skipped: [],
      undo_until: new Date(Date.now() + 10_000).toISOString(), sentence: "Assign to Priya N.: 1,200 Issues changed." });
    if (p === "/v2/issue-batches/b1/undo") return json({ restored: 1200, kept: 0, sentence: "Undone: 1,200 Issues back as they were." });
    if (p === "/v2/issue-views/import") return json({ imported: [VIEWS[0]], skipped: 0 });
    if (p.startsWith("/assets/") && p.endsWith("/overview")) return json({ asset: { label: "acme/api" } });
    return json({}, 404);
  }));
  return calls;
}

let root: Root | null = null;
const flush = (ms = 50) => act(async () => { await new Promise((r) => setTimeout(r, ms)); });
async function mount(el: React.ReactElement) {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(el));
  await flush(80);
  return host;
}
const button = (scope: ParentNode, text: string) =>
  Array.from(scope.querySelectorAll("button")).find((b) => (b.getAttribute("aria-label") ?? b.textContent ?? "").trim().startsWith(text)) as HTMLButtonElement;
async function type(el: HTMLInputElement | HTMLTextAreaElement, value: string) {
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(el, value);
  await act(async () => el.dispatchEvent(new Event("input", { bubbles: true })));
}
const searches = (calls: Call[]) => calls.filter((c) => c.path === "/v2/issues");
const queryInput = () => document.querySelector<HTMLInputElement>(".iss-query-input")!;

beforeEach(() => {
  vi.stubGlobal("matchMedia", (q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {} }));
  window.history.replaceState(null, "", "/app/issues");
  localStorage.clear();
});
afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("issue list helpers", () => {
  it("makes one removable chip per value, and counts each group's filters", () => {
    const q = parse('severity:critical,high -status:accepted first_seen:>30d "sql injection"');
    expect(chipsOf(q).map((c) => c.label)).toEqual([
      "Status: not Accepted", "Severity: Critical", "Severity: High", "First seen: more than 30 days ago", "Title has “sql injection”"]);
    const fewer = chipsOf(q)[1]!.remove(q);
    expect(formatQuery(fewer)).toBe('-status:accepted severity:high first_seen:>30d "sql injection"');
    expect(activeCount(q, ["severity", "priority"])).toBe(2);
    expect(formatQuery(toggled(q, "status", "accepted", true))).toContain("status:accepted");
    expect(formatQuery(toggled(q, "status", "accepted", true))).not.toContain("-status");
  });

  it("turns a view saved in the browser into a query for its project", () => {
    expect(legacyToQuery({ assetId: "a", name: "Mine", query: { severity: ["CRITICAL"], triage: ["not_a_risk"], priority: ["p1"],
      sla: ["breached"], tag: ["PCI-scope"], category: "sca", sort: "severity" } }, "acme/payments api")).toEqual({
      name: "Mine", sort: "severity",
      query: 'status:not_a_risk severity:critical priority:P1 sla:breached project:"acme/payments api" category:sca tag:PCI-scope' });
    localStorage.setItem("bulwark.savedViews.a1", JSON.stringify([{ name: "One", query: { severity: [] } }, { bad: true }]));
    localStorage.setItem("bulwark.savedViews.a2", "not json");
    localStorage.setItem("other", "[]");
    expect(readLegacyViews(localStorage)).toEqual([{ assetId: "a1", name: "One", query: { severity: [] } }]);
  });
});

describe("the Issues list", () => {
  it("reads its filters from the address, shows them in the panel and as chips, and is accessible", async () => {
    const calls = api();
    const host = await mount(<IssuesScreen initialQuery="severity:critical,high -status:accepted" initialSort="newest" initialView="" />);
    const first = searches(calls)[0]!;
    expect(first.params.get("q")).toBe("-status:accepted severity:critical,high");
    expect(first.params.get("sort")).toBe("newest");
    expect(host.querySelector(".iss-total")!.textContent).toBe("1,204 Issues");
    const critical = [...host.querySelectorAll<HTMLLabelElement>(".iss-check")].find((l) => l.textContent === "Critical")!;
    expect(critical.querySelector("input")!.checked).toBe(true);
    expect([...host.querySelectorAll(".iss-chips li > span")].map((s) => s.textContent)).toEqual(
      ["Status: not Accepted", "Severity: Critical", "Severity: High"]);
    expect(host.textContent).toContain("2 active"); // the Severity and priority group
    expect((await axe.run(host, AXE)).violations).toEqual([]);
  });

  it("keeps the panel, the query bar and the address in step, both ways", async () => {
    const calls = api();
    const host = await mount(<IssuesScreen initialQuery="" initialSort="" initialView="" />);
    const p1 = [...host.querySelectorAll<HTMLLabelElement>(".iss-check")].find((l) => l.textContent === "P1")!.querySelector("input")!;
    await act(async () => p1.click());
    await flush();
    expect(queryInput().value).toBe("priority:P1");
    expect(window.location.search).toBe("?q=priority%3AP1");
    expect(searches(calls).at(-1)!.params.get("q")).toBe("priority:P1");

    await type(queryInput(), "priority:P1 sla:breached");
    expect(host.querySelector(".iss-chips")!.textContent).toContain("SLA: Past SLA"); // the panel and chips follow at once
    await flush(700);
    expect(searches(calls).at(-1)!.params.get("q")).toBe("priority:P1 sla:breached");

    await act(async () => button(host, "Remove filter Priority: P1").click());
    await flush();
    expect(queryInput().value).toBe("sla:breached");
    expect(p1.checked).toBe(false);
    await act(async () => button(host, "Clear all").click());
    await flush();
    expect(queryInput().value).toBe("");
    expect(window.location.search).toBe("");
  });

  it("underlines a mistake where it is and does not run the query", async () => {
    const calls = api();
    const host = await mount(<IssuesScreen initialQuery="" initialSort="" initialView="" />);
    const before = searches(calls).length;
    await type(queryInput(), "severity:huge");
    await flush(700);
    expect(queryInput().getAttribute("aria-invalid")).toBe("true");
    expect(host.querySelector(".iss-echo mark")!.textContent).toBe("huge");
    expect(host.querySelector('[role="alert"]')!.textContent).toContain("is not a severity");
    expect(searches(calls).length).toBe(before);
    expect((await axe.run(host, AXE)).violations).toEqual([]);
  });

  it("offers keys and then values as you type", async () => {
    api();
    const host = await mount(<IssuesScreen initialQuery="" initialSort="" initialView="" />);
    const input = queryInput();
    await type(input, "sev");
    const options = () => [...host.querySelectorAll('[role="option"]')].map((o) => o.querySelector("code")!.textContent);
    expect(options()).toEqual(["severity:"]);
    expect(input.getAttribute("aria-expanded")).toBe("true");
    await act(async () => input.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true })));
    await act(async () => input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true })));
    await flush(30);
    expect(input.value).toBe("severity:");
    expect(options()).toEqual(["critical", "high", "medium", "low", "info"]);
    await type(input, "project:pay");
    await flush(250);
    expect(options()).toEqual(["acme/payments-api"]);
  });

  it("selects every matching Issue, previews the change, applies it with the count, and undoes it", async () => {
    const calls = api();
    const host = await mount(<IssuesScreen initialQuery="priority:P1" initialSort="" initialView="" />);
    await act(async () => host.querySelector<HTMLInputElement>('thead input[type="checkbox"]')!.click());
    expect(host.querySelector(".iss-picked")!.textContent).toBe("50 selected");
    await act(async () => button(host, "Select all 1,204 matching").click());
    expect(host.querySelector(".iss-picked")!.textContent).toBe("All 1,204 matching selected");
    await act(async () => button(host.querySelector(".iss-bulkbar")!, "Assign").click());
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]')!;
    expect(dialog.textContent).toContain("Assign: all 1,204 matching");
    await type(dialog.querySelector("input")!, "@priya");
    await act(async () => button(dialog, "Preview the change").click());
    await flush();
    expect(dialog.textContent).toContain("1,200 Issues will change. 4 Issues already are as asked.");
    expect((await axe.run(dialog, AXE)).violations).toEqual([]);
    await act(async () => button(dialog, "Change 1,200 Issues").click());
    await flush();
    const applied = calls.find((c) => c.path === "/v2/issues/bulk")!;
    expect(applied.body).toEqual({ q: "priority:P1", action: "assign", params: { to: "@priya" }, expected_count: 1204 });
    expect(host.querySelector(".iss-undo")!.textContent).toContain("1,200 Issues changed.");
    await act(async () => button(host, "Undo").click());
    await flush();
    expect(calls.some((c) => c.path === "/v2/issue-batches/b1/undo")).toBe(true);
    expect(host.querySelector(".iss-said")!.textContent).toBe("Undone: 1,200 Issues back as they were.");
  });

  it("sends only the picked Issues when not every match is selected", async () => {
    const calls = api();
    const host = await mount(<IssuesScreen initialQuery="" initialSort="" initialView="" />);
    await act(async () => host.querySelector<HTMLInputElement>('input[aria-label="Select Issue number 3"]')!.click());
    await act(async () => button(host.querySelector(".iss-bulkbar")!, "Reopen").click());
    await flush();
    const preview = calls.find((c) => c.path === "/v2/issues/bulk/preview")!;
    expect(preview.body).toEqual({ q: "", ids: ["i3"], action: "reopen", params: {} });
  });

  it("sends risk acceptance to its own flow, one request per project", async () => {
    const calls = api();
    const host = await mount(<IssuesScreen initialQuery="" initialSort="" initialView="" />);
    await act(async () => host.querySelector<HTMLInputElement>('thead input[type="checkbox"]')!.click());
    await act(async () => button(host.querySelector(".iss-bulkbar")!, "Request risk acceptance").click());
    await flush();
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]')!;
    expect(dialog.textContent).toContain("one request per project, which a second person approves");
    expect(button(dialog, "Change")).toBeUndefined(); // never applied as a bulk change
    await act(async () => button(dialog, "Request risk acceptance for acme/ledger").click());
    await flush();
    expect(dialog.querySelector(".iss-subflow h3")!.textContent).toBe("acme/ledger");
    expect(calls.some((c) => c.path === "/v2/issues/bulk")).toBe(false);
  });

  it("shows more by cursor, and remembers columns and density for the person", async () => {
    const calls = api();
    const host = await mount(<IssuesScreen initialQuery="" initialSort="" initialView="" />);
    await act(async () => button(host, "Show 50 more").click());
    await flush();
    expect(searches(calls).at(-1)!.params.get("after")).toBe("c1");
    expect(host.querySelectorAll("tbody tr").length).toBe(100);
    await act(async () => button(host, "Columns").click());
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]')!;
    const path = [...dialog.querySelectorAll<HTMLLabelElement>(".iss-check")].find((l) => l.textContent === "Location")!;
    await act(async () => path.querySelector("input")!.click());
    await act(async () => dialog.querySelector<HTMLInputElement>('input[type="radio"]:not(:checked)')!.click());
    await act(async () => button(dialog, "Apply").click());
    await flush();
    const put = calls.find((c) => c.path === "/v2/me/tables/issues" && c.method === "PUT")!;
    expect(put.body).toEqual({ columns: ["project", "priority", "severity", "status", "sla", "assignee", "first_seen", "path"], density: "compact" });
    expect([...host.querySelectorAll("thead th")].at(-1)!.textContent).toBe("Location");
    expect(host.querySelector(".iss")!.classList.contains("iss-compact")).toBe(true);
  });

  it("opens a saved view, carries it in the address, and saves the list as a new view", async () => {
    const calls = api();
    const host = await mount(<IssuesScreen initialQuery="" initialSort="" initialView="v1" />);
    await flush();
    expect(window.location.search).toContain("view=v1");
    await act(async () => button(host, "Assigned to me").click());
    await flush();
    expect(queryInput().value).toBe("assignee:me");
    expect(window.location.search).toBe("?q=assignee%3Ame&view=builtin%3Amine");
    expect(button(host, "Copy to my views")).toBeTruthy();
    await act(async () => button(host, "Save as a view").click());
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]')!;
    await type(dialog.querySelector("input")!, "Mine, at a glance");
    await act(async () => dialog.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click()); // share with leads
    await act(async () => button(dialog, "Save").click());
    await flush();
    const post = calls.find((c) => c.path === "/v2/issue-views" && c.method === "POST")!;
    expect(post.body).toMatchObject({ name: "Mine, at a glance", query: "assignee:me", sort: "priority", shared_with: ["lead"] });
  });

  it("offers to import views saved in this browser, once", async () => {
    localStorage.setItem("bulwark.savedViews.a1", JSON.stringify([{ name: "Old", query: { severity: ["HIGH"], triage: [], category: "", sort: "risk" } }]));
    const calls = api();
    const host = await mount(<IssuesScreen initialQuery="" initialSort="" initialView="" />);
    expect(host.querySelector(".iss-import")!.textContent).toContain("1 view is saved in this browser");
    await act(async () => button(host, "Import").click());
    await flush();
    const sent = calls.find((c) => c.path === "/v2/issue-views/import")!;
    expect(sent.body).toEqual({ views: [{ name: "Old", query: "severity:high project:acme/api", sort: "priority" }] });
    expect(host.querySelector(".iss-import")).toBeNull();
    expect(localStorage.getItem(LEGACY_DONE)).toBeTruthy();
    expect(host.textContent).toContain("Imported 1 view.");
  });
});
