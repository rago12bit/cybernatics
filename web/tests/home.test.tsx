// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RoleHome } from "../components/home/RoleHome";
import { UnitOverviewScreen } from "../components/home/UnitOverviewScreen";
import { ago, dueWords, type Me, type UnitOverview, type UnitProject } from "../lib/dashboard";

vi.mock("next/navigation", () => ({ usePathname: () => "/app", useRouter: () => ({ push: vi.fn(), replace: vi.fn() }) }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const AXE = { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const project = (label: string, over: Partial<UnitProject> = {}): UnitProject => ({
  asset: `id-${label}`, label, open: 3, open_p1: 0, past_sla: 0, new_advisories: [], last_scan_at: new Date(Date.now() - 3 * 3600e3).toISOString(),
  days_since_scan: 0, scanners_ok: 7, scanners_applicable: 7, trend: [1, 2, 3, 3, 3, 3, 3, 3], needs: [], ...over,
});
const UNIT: UnitOverview = {
  id: "u1", name: "Payments", needs_attention: 2, stale_days: 14, trend_weeks: 8, generated_at: "2026-10-07T00:00:00Z",
  verdict: "2 projects need attention: 4 issues are past SLA and reporting-svc hasn't been scanned in 19 days. The other 5 projects are on track.",
  projects: [
    project("partner-gateway", { open_p1: 3, past_sla: 4, scanners_ok: 6, needs: ["past_sla", "new_advisory"], new_advisories: ["CVE-2026-1"] }),
    project("reporting-svc", { days_since_scan: 19, last_scan_at: new Date(Date.now() - 19 * 86400e3).toISOString(), scanners_ok: 4, needs: ["not_scanned"] }),
    ...["a", "b", "c", "d", "e"].map((x) => project(`svc-${x}`)),
  ],
};

function api(me: Me | null, role?: string) {
  const calls: { method: string; path: string; body?: unknown }[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ method, path: u.pathname, body });
    if (u.pathname === "/v2/me") return me ? json(me) : json({}, 401);
    if (u.pathname === "/v2/me/role") return json({ ...me, role: (body as { role: string }).role });
    if (u.pathname === "/v2/me/assigned") return json({ total: 2, rows: [
      { issue_id: "i1", project_id: "p", project: "acme/api", title: "SQL injection", band: "P1", severity: "HIGH", due_at: null, days_left: -3 },
      { issue_id: "i2", project_id: "p", project: "acme/api", title: "Open redirect", band: "P3", severity: "LOW", due_at: null, days_left: 5 }] });
    if (u.pathname === "/v2/me/engagements") return json([{ id: "e1", name: "Q4 test", type: "pentest", status: "active", project_id: "p",
      project: "acme/api", as: ["tester"], target_end_at: "2026-10-01T00:00:00Z", overdue: true }]);
    if (u.pathname === "/v2/portfolio-overviews/u1") return json(UNIT);
    if (u.pathname === "/v2/portfolio-overviews") return json([{ id: "u1", name: "Payments", verdict: UNIT.verdict, needs_attention: 2, projects: 7 }]);
    if (u.pathname === "/v2/dashboards") return json({ role, dashboards: [{ id: "builtin:program", name: "Program overview", owner: null,
      shared_with: ["lead"], widgets: [], version: 0, updated_at: null, updated_by: null, builtin: true, can_edit: false }] });
    if (u.pathname === "/v2/metrics" || u.pathname === "/v2/portfolios" || u.pathname === "/assets") return json([]);
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
  await flush();
  return host;
}
const button = (scope: ParentNode, text: string) =>
  Array.from(scope.querySelectorAll("button")).find((b) => b.textContent?.trim().startsWith(text)) as HTMLButtonElement;
const ME = (role: Me["role"]): Me => ({ actor: "token:abc", person: true, role, roles: ["lead", "engineer", "tester"] });
const FALLBACK = <h1>Scan a codebase</h1>;

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  vi.stubGlobal("matchMedia", (q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {} }));
});
afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("role homes", () => {
  it("leaves the shared token on the scan page", async () => {
    api({ actor: "shared-token", person: false, role: null, roles: ["lead", "engineer", "tester"] });
    const host = await mount(<RoleHome fallback={FALLBACK} />);
    expect(host.querySelector("h1")!.textContent).toBe("Scan a codebase");
    expect(host.querySelector(".home-picker")).toBeNull();
  });

  it("asks a person what they do, keeps the scan page below, then lands them on their home", async () => {
    const calls = api(ME(null), "lead");
    const host = await mount(<RoleHome fallback={FALLBACK} />);
    expect(host.querySelector(".home-picker h2")!.textContent).toBe("What do you do here?");
    expect(host.textContent).toContain("Scan a codebase");
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    const lead = host.querySelectorAll<HTMLInputElement>(".home-picker input[type=radio]")[0]!;
    expect(lead.closest("label")!.textContent).toContain("Lead");
    await act(async () => lead.click());
    await act(async () => button(host, "Save").click());
    await flush(80);
    expect(calls.find((c) => c.method === "PUT")).toMatchObject({ path: "/v2/me/role", body: { role: "lead" } });
    expect(host.querySelector(".eyebrow")!.textContent).toBe("Home · Lead");
    expect(host.querySelector("h1")!.textContent).toBe("Program overview"); // the program dashboard
    expect(host.querySelector(".home-units-list")!.textContent).toContain("2 projects need attention");
    expect(host.textContent).not.toContain("What do you do here?");
  });

  it("lands an engineer on their issues, the overdue first", async () => {
    api(ME("engineer"));
    const host = await mount(<RoleHome fallback={FALLBACK} />);
    expect(host.querySelector("h1")!.textContent).toBe("Assigned to you");
    expect(host.querySelector("caption")!.textContent).toBe("2 open issues, the soonest SLA deadline first");
    const cells = [...host.querySelectorAll("tbody td:last-child")].map((td) => td.textContent);
    expect(cells).toEqual(["3 days overdue", "Due in 5 days"]);
    expect(host.querySelector("tbody a")!.getAttribute("href")).toBe("/app/projects/p/issues/i1");
    expect((await axe.run(host, AXE)).violations).toEqual([]);
  });

  it("lands a tester on their engagements, and lets them change role", async () => {
    api(ME("tester"));
    const host = await mount(<RoleHome fallback={FALLBACK} />);
    expect(host.querySelector("h1")!.textContent).toBe("Your engagements");
    expect(host.querySelector("tbody tr")!.textContent).toContain("2026-10-01 (overdue)");
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    await act(async () => button(host, "Change role").click());
    const checked = [...host.querySelectorAll<HTMLInputElement>(".home-picker input")].find((i) => i.checked)!;
    expect(checked.closest("label")!.textContent).toContain("Tester");
  });
});

describe("the portfolio overview", () => {
  it("says what needs attention, lists the neediest first, and folds the rest on track", async () => {
    api(ME("lead"));
    const host = await mount(<UnitOverviewScreen id="u1" />);
    expect(host.querySelector(".home-verdict")!.textContent).toBe(UNIT.verdict);
    const rows = () => [...host.querySelectorAll("tbody tr th")].map((th) => th.textContent);
    expect(rows()).toEqual(["partner-gateway", "reporting-svc", "svc-a", "svc-b"]); // 2 needing + 2 on track = 4 shown
    expect(host.querySelector(".home-more")!.textContent).toContain("3 more, on track.");
    const first = host.querySelector("tbody tr")!;
    expect(first.querySelector("td:nth-child(5)")!.textContent).toBe("6 of 7");
    expect(first.querySelector("td:nth-child(3) a")!.getAttribute("href"))
      .toBe("/app/metrics/issues?portfolio=u1&kind=past_sla&in_project=id-partner-gateway&label=Past+SLA%2C+partner-gateway&n=4");
    expect(first.querySelector("svg")!.getAttribute("aria-label")).toBe("Unfixed issues in partner-gateway: up, from 1 to 3 over 8 weeks");
    expect(first.textContent).toContain("Past SLA, New advisory (CVE-2026-1)");
    expect(host.querySelectorAll("tbody tr")[1]!.querySelector("td:nth-child(4)")!.textContent).toBe("19 days ago");
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    await act(async () => button(host, "Show all 7").click());
    expect(rows()).toHaveLength(7);
    expect(host.querySelector(".home-more")).toBeNull();
  });

  it("words times and deadlines plainly", () => {
    const now = Date.parse("2026-10-07T12:00:00Z");
    expect(ago("2026-10-07T10:00:00Z", now)).toBe("2 hours ago");
    expect(ago("2026-10-06T12:00:00Z", now)).toBe("1 day ago");
    expect(ago("2026-09-18T12:00:00Z", now)).toBe("19 days ago");
    expect(ago(null, now)).toBe("never");
    expect([dueWords(-1), dueWords(0), dueWords(1), dueWords(null)]).toEqual(["1 day overdue", "Due today", "Due in 1 day", "No SLA"]);
  });
});
