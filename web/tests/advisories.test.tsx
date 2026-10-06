// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AdvisoriesScreen, feedsLine } from "../components/AdvisoriesScreen";
import { AdvisoryScreen, fixLine, impactSentence } from "../components/AdvisoryScreen";
import type { AdvisoryImpact, AdvisorySummary, AdvisoryUse } from "../lib/types";

vi.mock("next/navigation", () => ({ usePathname: () => "/app", useRouter: () => ({ push: vi.fn() }) }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

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

const use = (over: Partial<AdvisoryUse>): AdvisoryUse => ({
  project_id: "p1", project: "payments-api", portfolio: "Payments", library: "org.apache.logging.log4j:log4j-core",
  ecosystem: "maven", purl: "pkg:maven/org.apache.logging.log4j/log4j-core", version: "2.14.1", fixed_version: "2.15.0",
  certain: true, resolved_at: null, first_seen_at: "2026-10-06T08:00:00Z", relation: "transitive", paths: ["pom.xml"],
  reachable: true, reachable_reason: "Imported by application code (App.java)", exposure: "internet", owner: "Priya N.",
  issues: [], ...over,
});
const USES = [
  use({}),
  use({ project_id: "p2", project: "partner-gateway", version: "2.0-beta9", fixed_version: "2.3.1", reachable: null, owner: null }),
  ...Array.from({ length: 6 }, (_, i) => use({ project_id: `q${i}`, project: `svc-${i}`, reachable: false, exposure: "internal", owner: null })),
];
const IMPACT: AdvisoryImpact = {
  vuln_key: "CVE-2021-44228", ids: ["GHSA-jfh8-c2jp-5v3q"], aliases: ["CVE-2021-44228"], cves: ["CVE-2021-44228"],
  summary: "Remote code injection in Log4j", details: "Apache Log4j2 2.0-beta9 through 2.15.0 ...", severity: "CRITICAL",
  cvss: 10, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", malicious: false,
  kev: { cve: "CVE-2021-44228", date_added: "2021-12-10", due_date: "2021-12-24", name: "Log4j", ransomware: "Known" },
  published: "2021-12-10T00:00:00Z", modified: "2026-01-01T00:00:00Z",
  references: ["https://logging.apache.org/log4j/2.x/security.html", "javascript:alert(1)"], withdrawn: false,
  state: "new", first_seen_at: "2026-10-06T07:00:00Z", uses: USES, no_longer_affected: [],
  summary_counts: { projects: 8, portfolios: 1, imported_by_app: 1, internet_facing: 2, uncertain: 0, with_fix: 8, with_issues: 0 },
};

describe("the words", () => {
  it("say where, how used and how to fix, without claiming code is unreachable", () => {
    expect(impactSentence(IMPACT)).toBe("An affected version is in 8 projects across 1 business unit. 1 of them imports it from application code.");
    expect(impactSentence({ ...IMPACT, summary_counts: { ...IMPACT.summary_counts, imported_by_app: 0, uncertain: 2 } }))
      .toBe("An affected version is in 8 projects across 1 business unit. None is known to import it from application code. For 2, the version could not be compared.");
    expect(fixLine(USES)).toBe("Fix: upgrade log4j-core to 2.15.0 or 2.3.1.");
    expect(fixLine([use({ fixed_version: null })])).toBe("No fixed version is listed.");
    expect(feedsLine({ feeds: [], advisories: 0, kev_entries: 0 })).toContain("No advisory data yet");
    const now = Date.parse("2026-10-06T12:00:00Z");
    expect(feedsLine({ advisories: 273000, kev_entries: 1484, feeds: [
      { source: "osv:Maven", last_run_at: null, last_success_at: "2026-10-06T10:00:00Z", records: 7168, last_error: null },
      { source: "nvd", last_run_at: null, last_success_at: null, records: 0, last_error: "HTTPError: 503" },
    ] }, now)).toBe("273,000 advisories (OSV updated 2 h ago), 1,484 known exploited. Last update failed for nvd.");
  });
});

describe("the advisory screens", () => {
  it("lists what affects us and filters it", async () => {
    const calls: string[] = [];
    const row: AdvisorySummary = { vuln_key: "CVE-2021-44228", ids: ["GHSA-jfh8-c2jp-5v3q"], summary: "Remote code injection in Log4j",
      severity: "CRITICAL", cvss: 10, kev: true, malicious: false, published: null, first_seen_at: "2026-10-06T07:00:00Z",
      state: "new", projects: 8, libraries: ["org.apache.logging.log4j:log4j-core"], imported_by_app: 1, internet_facing: 2, uncertain: 0 };
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      const u = new URL(String(url));
      calls.push(u.pathname + u.search);
      if (u.pathname === "/v2/advisory-feeds") return json({ feeds: [], advisories: 0, kev_entries: 0 });
      if (u.pathname === "/v2/advisories") return json(u.searchParams.get("state") === "issues" ? [] : [row]);
      return json({}, 404);
    }));
    const host = document.createElement("div");
    document.body.replaceChildren(host);
    root = createRoot(host);
    await act(async () => root!.render(<AdvisoriesScreen />));
    await flush();
    expect(host.querySelector(".ds-adv-key")?.getAttribute("href")).toBe("/app/advisories/CVE-2021-44228");
    expect(host.textContent).toContain("in 8 projects, 2 internet-facing, 1 importing it from application code");
    expect(host.querySelector(".ds-adv-kev")?.textContent).toBe("Known exploited");
    expect((await axe.run(host, AXE)).violations.map((v) => v.id)).toEqual([]);
    const issues = Array.from(host.querySelectorAll<HTMLInputElement>("input[type=radio]")).find((i) => i.value === "issues")!;
    await act(async () => issues.click());
    await flush();
    expect(calls.at(-1)).toBe("/v2/advisories?state=issues");
    expect(host.textContent).toContain("Nothing matches.");
  });

  it("shows the impact, the most important uses first, and creates Issues in one click", async () => {
    const calls: { url: string; method: string }[] = [];
    let state: AdvisoryImpact = IMPACT;
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      const u = new URL(String(url));
      calls.push({ url: u.pathname, method: init?.method ?? "GET" });
      if (u.pathname.endsWith("/issues")) {
        state = { ...IMPACT, state: "issues", uses: USES.map((x) => ({ ...x, issues: [{ id: `i-${x.project_id}`, state: "new" }] })) };
        return json({ projects: 8, issues: 8, tickets: 3, ticket_errors: ["svc-1: Jira said 401"], issue_ids: {} });
      }
      if (u.pathname === "/v2/advisories/CVE-2021-44228") return json(state);
      return json({}, 404);
    }));
    const host = document.createElement("div");
    document.body.replaceChildren(host);
    root = createRoot(host);
    await act(async () => root!.render(<AdvisoryScreen vulnKey="CVE-2021-44228" />));
    await flush();
    expect(host.querySelector("h1")?.textContent).toBe("CVE-2021-44228");
    expect(host.querySelector(".ds-adv-kev")?.textContent).toContain("due 2021-12-24");
    expect(host.querySelectorAll(".ds-adv-table tbody tr")).toHaveLength(5);
    expect(host.querySelector(".ds-adv-more")?.textContent).toContain("3 more uses, none imported by application code");
    expect(host.querySelector(".ds-adv-fix")?.textContent).toBe("Fix: upgrade log4j-core to 2.15.0 or 2.3.1.");
    expect(host.textContent).not.toMatch(/unreachable/i);
    expect(Array.from(host.querySelectorAll(".ds-adv-plain a")).map((a) => a.getAttribute("href"))).toEqual(["https://logging.apache.org/log4j/2.x/security.html"]);
    expect((await axe.run(host, AXE)).violations.map((v) => v.id)).toEqual([]);
    await act(async () => (host.querySelector(".ds-adv-more button") as HTMLButtonElement).click());
    expect(host.querySelectorAll(".ds-adv-table tbody tr")).toHaveLength(8);
    const create = Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.startsWith("Create Issues in 8 projects"))!;
    await act(async () => create.click());
    await flush();
    expect(calls.some((c) => c.url === "/v2/advisories/CVE-2021-44228/issues" && c.method === "POST")).toBe(true);
    expect(host.querySelector("[role=status]")?.textContent).toBe("8 Issues in 8 projects; 3 tickets filed or updated. Tickets failed: svc-1: Jira said 401.");
    expect(Array.from(host.querySelectorAll("button")).some((b) => b.textContent === "Bring the Issues up to date")).toBe(true);
    expect(host.querySelector(".ds-adv-table tbody tr a[href='/app/projects/p1/issues/i-p1']")).not.toBeNull();
  });
});
