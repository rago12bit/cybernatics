// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CalendarScreen, agendaFor, calendarVerdict, monthGrid, onDay } from "../components/CalendarScreen";
import type { CalendarEntry, CalendarView } from "../lib/types";

vi.mock("next/navigation", () => ({ usePathname: () => "/app", useRouter: () => ({ push: vi.fn() }) }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const P = "11111111-1111-4111-8111-111111111111";
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
let root: Root | null = null;
const flush = (ms = 40) => act(async () => { await new Promise((r) => setTimeout(r, ms)); });
afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});
const AXE = { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } };

const entry = (over: Partial<CalendarEntry>): CalendarEntry => ({
  kind: "sla", start: "2026-10-09", end: "2026-10-09", title: "SQL injection", project_id: P, project: "payments-api",
  link: `/app/projects/${P}/issues/x`, detail: "Critical, P1: SLA due", severity: "CRITICAL", state: "on_track", ...over,
});

const ENTRIES: CalendarEntry[] = [
  entry({ kind: "engagement", start: "2026-09-29", end: "2026-10-03", title: "Q4 pentest", link: "/app/engagements/e", detail: "pentest, in progress", severity: null, state: "in_progress" }),
  entry({ start: "2026-10-02", end: "2026-10-02", title: "Hard-coded key", state: "breached", detail: "High: SLA breached" }),
  entry({}),
  entry({ kind: "acceptance", start: "2026-10-20", end: "2026-10-20", title: "Accept: 2 issues", link: "/app/risk-acceptances/r", detail: "expires", severity: null, state: "approved" }),
];

describe("calendar arithmetic", () => {
  it("lays out whole weeks, Monday first, in UTC", () => {
    const days = monthGrid(2026, 9).map((d) => d.toISOString().slice(0, 10));
    expect(days[0]).toBe("2026-09-28"); // 1 October 2026 is a Thursday
    expect(days.at(-1)).toBe("2026-11-01");
    expect(days).toHaveLength(35);
    expect(monthGrid(2027, 1)).toHaveLength(28); // February 2027: Monday the 1st to Sunday the 28th
    expect(monthGrid(2026, 1)).toHaveLength(35); // February 2026 starts on a Sunday
  });

  it("spans engagements across days in the grid and names them once in the list", () => {
    expect(onDay(ENTRIES, "2026-10-02").map((e) => e.title)).toEqual(["Q4 pentest", "Hard-coded key"]);
    expect(agendaFor(ENTRIES, "2026-10-02", "2026-10-01", "2026-10-01").map((e) => e.title)).toEqual(["Hard-coded key"]);
    expect(agendaFor(ENTRIES, "2026-10-01", "2026-10-01", "2026-10-01").map((e) => e.title)).toEqual(["Q4 pentest"]);
    expect(calendarVerdict({ start: "", end: "", entries: ENTRIES, counts: { engagement: 1, sla: 2, acceptance: 1 }, truncated: [] }, "2026-10-06"))
      .toBe("This month: 1 SLA already breached, 1 still to fall due, 1 risk acceptance expiring.");
  });
});

describe("calendar screen", () => {
  it("asks for the whole grid, shows each kind, filters, and is accessible", async () => {
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      const u = new URL(String(url));
      calls.push(u.pathname + u.search);
      if (u.pathname === "/assets") return json([{ id: P, label: "payments-api" }]);
      if (u.pathname === "/v2/calendar") {
        const kinds = (u.searchParams.get("kinds") ?? "").split(",");
        const view: CalendarView = { start: u.searchParams.get("from")!, end: u.searchParams.get("to")!,
          entries: ENTRIES.filter((e) => kinds.includes(e.kind)), counts: { engagement: 1, sla: 2, acceptance: 1 }, truncated: [] };
        return json(view);
      }
      return json({}, 404);
    }));
    const host = document.createElement("div");
    document.body.replaceChildren(host);
    root = createRoot(host);
    await act(async () => root!.render(<CalendarScreen initial={{ year: 2026, month: 9 }} />));
    await flush();
    expect(calls.find((c) => c.startsWith("/v2/calendar"))).toBe("/v2/calendar?from=2026-09-28&to=2026-11-01&kinds=engagement%2Csla%2Cacceptance");
    expect(host.querySelector(".ds-cal-month")?.textContent).toContain("2026");
    const chips = Array.from(host.querySelectorAll(".ds-cal-chip")).map((c) => c.textContent);
    expect(chips.filter((c) => c === "Engagement Q4 pentest")).toHaveLength(5); // 29 Sep to 3 Oct
    expect(host.querySelector(".ds-cal-breached")?.textContent).toBe("SLA Hard-coded key");
    const agenda = Array.from(host.querySelectorAll(".ds-cal-days > li h3")).map((h) => h.textContent);
    expect(agenda).toHaveLength(4); // 1 Oct (the pentest, begun in September), 2, 9 and 20 Oct
    const results = await axe.run(host, AXE);
    expect(results.violations.map((v) => v.id)).toEqual([]);
    const sla = host.querySelector<HTMLInputElement>(".ds-cal-toggle.ds-cal-sla input")!;
    await act(async () => sla.click());
    await flush();
    expect(calls.at(-1)).toContain("kinds=engagement%2Cacceptance");
    expect(host.querySelectorAll(".ds-cal-sla.ds-cal-chip")).toHaveLength(0);
    await act(async () => (host.querySelector('[aria-label="Next month"]') as HTMLButtonElement).click());
    await flush();
    expect(calls.at(-1)).toContain("from=2026-10-26&to=2026-12-06");
  });
});
