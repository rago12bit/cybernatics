// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ReportBuilder } from "../components/reports/ReportBuilder";
import { ReportsScreen } from "../components/reports/ReportsScreen";
import { idFrom, moveBlock, newBlock, scheduleWords, type Block, type Report, type ReportRun } from "../lib/reports";

const push = vi.fn();
vi.mock("next/navigation", () => ({ usePathname: () => "/app/reports", useRouter: () => ({ push, replace: vi.fn() }) }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const AXE = { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const BLOCKS: Block[] = [
  { id: "cover", type: "cover", config: { title: "Weekly", subtitle: "" } },
  { id: "summary", type: "summary", config: { text: "", source: "person" } },
  { id: "sla", type: "metric", config: { metric: "sla_adherence", filters: {} } },
  { id: "appendix", type: "appendix", config: {} },
];
const REPORT: Report = {
  id: "r1", name: "Weekly program summary", owner: "token:p", period_days: 7, blocks: BLOCKS, schedule: null,
  next_run_at: null, version: 1, updated_at: "2026-10-07T00:00:00Z", updated_by: "token:p", summary_needs_review: false,
};
const RUN: ReportRun = {
  id: "run1", report_id: "r1", report_name: "Weekly program summary", trigger: "manual", status: "done", error: null, period: ["2026-10-01", "2026-10-07"],
  sha256: "c74ea26be229abd85dc769394985b7f32d8d4a531cd8a8a746269feb3a7a00de", signed: true, size: 103000, ai_summary: false,
  delivery: [], created_by: "token:p", created_at: "2026-10-07T05:00:00Z",
};

type Call = { method: string; path: string; body?: unknown };
function api(o: { report?: Report; runs?: ReportRun[] } = {}) {
  const calls: Call[] = [];
  let report = o.report ?? REPORT;
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ method, path: u.pathname, body });
    const p = u.pathname;
    if (p === "/v2/report-templates") return json([{ id: "program-weekly", name: "Weekly program summary", description: "For leads.", period_days: 7, blocks: BLOCKS }]);
    if (p === "/v2/reports" && method === "POST") return json({ ...REPORT, id: "new1" }, 201);
    if (p === "/v2/reports") return json([REPORT]);
    if (p === "/v2/reports/r1" && method === "PUT") { report = { ...report, ...(body as object), version: report.version + 1 }; return json(report); }
    if (p === "/v2/reports/r1") return json(report);
    if (p === "/v2/reports/r1/summary/draft") {
      report = { ...report, version: report.version + 1, summary_needs_review: true, blocks: report.blocks.map((b) => b.type === "summary"
        ? { ...b, config: { text: "Drafted text.", source: "ai", drafted_by_model: "claude-x", reviewed_by: null } } : b) };
      return json({ ...report, notes: ["1 possible secret(s) were removed from Issue titles before sending."] });
    }
    if (p === "/v2/reports/r1/summary/review") {
      report = { ...report, version: report.version + 1, summary_needs_review: false, blocks: report.blocks.map((b) => b.type === "summary"
        ? { ...b, config: { ...b.config, text: (body as { text: string }).text, reviewed_by: "token:p" } } : b) };
      return json(report);
    }
    if (p === "/v2/reports/r1/runs" && method === "POST") return json(RUN, 202);
    if (p === "/v2/reports/r1/runs") return json(o.runs ?? []);
    if (p === "/v2/report-runs/run1/links" && method === "POST") return json({ id: "l1", run_id: "run1", created_by: "token:p", created_at: "2026-10-07T05:01:00Z",
      expires_at: "2026-10-14T05:01:00Z", state: "active", revoked_by: null, opens: 0, last_opened_at: null, token: "tok", path: "/r/tok", url: null }, 201);
    if (p === "/v2/report-runs/run1/links") return json([]);
    if (p === "/v2/compliance/frameworks") return json([{ id: "owasp-top10-2021", name: "OWASP Top 10 2021" }]);
    if (p === "/v2/portfolios" || p === "/assets") return json([]);
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
const live = () => document.querySelector('[aria-live="polite"].sr-only')!.textContent;
async function type(el: HTMLInputElement | HTMLTextAreaElement, value: string) {
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(el, value);
  await act(async () => el.dispatchEvent(new Event("input", { bubbles: true })));
}

beforeEach(() => vi.stubGlobal("matchMedia", (q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {} })));
afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
  push.mockReset();
});

describe("report helpers", () => {
  it("finds the id in a pasted link", () => {
    expect(idFrom("http://x/app/projects/11111111-1111-4111-8111-111111111111/issues/22222222-2222-4222-8222-222222222222"))
      .toBe("22222222-2222-4222-8222-222222222222");
    expect(idFrom("nothing here")).toBeNull();
  });
  it("moves blocks a place at a time and makes unique ids", () => {
    expect(moveBlock(BLOCKS, "sla", -1).map((b) => b.id)).toEqual(["cover", "sla", "summary", "appendix"]);
    expect(moveBlock(BLOCKS, "cover", -1)).toBe(BLOCKS);
    expect(newBlock("metric", [...BLOCKS, { id: "metric-1", type: "metric", config: {} }]).id).toBe("metric-2");
    expect(scheduleWords({ cadence: "weekly", weekday: 0, day: 1, hour: 8, recipients: ["a@b.co"], link_days: 14 }))
      .toBe("Sent every Monday at 08:00 UTC to 1 recipient");
  });
});

describe("the reports list", () => {
  it("creates a report from a template and opens it", async () => {
    const calls = api();
    const host = await mount(<ReportsScreen />);
    expect(host.querySelector("tbody th a")!.textContent).toBe("Weekly program summary");
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    await act(async () => button(host, "Create").click());
    await flush();
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ template: "program-weekly" });
    expect(push).toHaveBeenCalledWith("/app/reports/new1");
  });
});

describe("the report builder", () => {
  it("reorders blocks from the keyboard, announces it, and saves the order", async () => {
    const calls = api();
    const host = await mount(<ReportBuilder reportId="r1" />);
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    expect(button(host, "Move Cover up").disabled).toBe(true);
    await act(async () => button(host, "Move Metric up").click());
    expect(live()).toBe("Metric moved to position 2 of 4.");
    expect([...host.querySelectorAll(".rep-block h3")].map((h) => h.textContent)).toEqual(
      ["1. Cover", "2. Metric", "3. Executive summary", "4. Appendix"]);
    await act(async () => button(host, "Save").click());
    await flush();
    const put = calls.find((c) => c.method === "PUT")!;
    expect((put.body as { blocks: Block[] }).blocks.map((b) => b.id)).toEqual(["cover", "sla", "summary", "appendix"]);
    expect(host.querySelector(".dash-notice")!.textContent).toBe("Saved.");
  });

  it("won't generate an AI draft until a person confirms it, then labels it", async () => {
    api();
    const host = await mount(<ReportBuilder reportId="r1" />);
    await act(async () => button(host, "Draft with AI").click());
    await flush();
    expect(host.querySelector(".rep-ai")!.textContent).toMatch(/^AI draft \(claude-x\), not reviewed yet/);
    expect(host.textContent).toContain("1 possible secret(s) were removed");
    expect(button(host, "Generate PDF").disabled).toBe(true);
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    const ta = host.querySelector<HTMLTextAreaElement>(".rep-block textarea")!;
    await type(ta, "Drafted text. Checked by me.");
    await act(async () => button(host, "Confirm this summary").click());
    await flush();
    expect(host.querySelector(".rep-ai")!.textContent).toMatch(/^Drafted by AI \(claude-x\).*reviewed/);
    expect(button(host, "Generate PDF").disabled).toBe(false);
  });

  it("locks drafting while other changes are unsaved", async () => {
    api();
    const host = await mount(<ReportBuilder reportId="r1" />);
    await type(host.querySelector<HTMLInputElement>(".rep-panel input")!, "Renamed");
    expect(button(host, "Draft with AI").disabled).toBe(true);
    expect(host.textContent).toContain("Save your other changes first.");
  });

  it("generates a PDF, shows its hash, and shows a new link once", async () => {
    api();
    const host = await mount(<ReportBuilder reportId="r1" />);
    await act(async () => button(host, "Generate PDF").click());
    await flush(80);
    expect(host.querySelector(".rep-hash")!.textContent).toBe(RUN.sha256);
    expect(host.querySelector(".rep-run")!.textContent).toContain("signed");
    await act(async () => button(host, "Create a link").click());
    await flush(80);
    const input = host.querySelector<HTMLInputElement>(".rep-link input")!;
    expect(input.value).toMatch(/\/r\/tok$/);
    expect(host.querySelector(".rep-link")!.textContent).toContain("It is shown only now");
    expect((await axe.run(host, AXE)).violations).toEqual([]);
  });

  it("sets a schedule and saves it with the report", async () => {
    const calls = api();
    const host = await mount(<ReportBuilder reportId="r1" />);
    const enable = [...host.querySelectorAll<HTMLInputElement>(".rep-check input")][0]!;
    await act(async () => enable.click());
    const to = [...host.querySelectorAll<HTMLTextAreaElement>("textarea")].find((t) => t.id.endsWith("-to"))!;
    await type(to, "lead@example.com\ncto@example.com");
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    await act(async () => button(host, "Save").click());
    await flush();
    const put = calls.find((c) => c.method === "PUT")!;
    expect((put.body as { schedule: { recipients: string[]; cadence: string } }).schedule).toMatchObject({
      cadence: "weekly", recipients: ["lead@example.com", "cto@example.com"] });
  });
});

describe("a queued report", () => {
  it("says it is being made, then shows the PDF when the worker is done", async () => {
    let polls = 0;
    api();
    const real = globalThis.fetch;
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      const u = new URL(String(url));
      if (u.pathname === "/v2/reports/r1/runs" && (init?.method ?? "GET") === "POST") return json({ ...RUN, status: "queued", sha256: "", size: 0 }, 202);
      if (u.pathname === "/v2/reports/r1/runs") { polls++; return json(polls > 1 ? [RUN] : [{ ...RUN, status: "queued", sha256: "", size: 0 }]); }
      return (real as typeof fetch)(url, init);
    }));
    const host = await mount(<ReportBuilder reportId="r1" />);
    await act(async () => button(host, "Generate PDF").click());
    await flush(80);
    expect(host.querySelector(".dash-notice")!.textContent).toBe("Queued. It appears below when it is ready.");
    expect(host.querySelector(".rep-run [role=status]")!.textContent).toBe("Being made. This takes a few seconds.");
    await flush(4300);
    expect(host.querySelector(".rep-hash")!.textContent).toBe(RUN.sha256);
  });
});
