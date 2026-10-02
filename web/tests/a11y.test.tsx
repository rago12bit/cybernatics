// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DemoReport } from "../components/DemoReport";
import { FindingDetail } from "../components/FindingDetail";
import { IssueDetail } from "../components/IssueDetail";
import { IssuesTable } from "../components/IssuesTable";
import { ProjectOverview } from "../components/ProjectOverview";
import { ProjectsList } from "../components/ProjectsList";
import { ScanComparison } from "../components/ScanComparison";
import { RecentScans } from "../components/RecentScans";
import { ScanReport } from "../components/ScanReport";
import { SubmitForm } from "../components/SubmitForm";
import { ModeProvider } from "../design-system/mode";
import { TooltipProvider } from "../design-system/primitives/Tooltip";
import { Landing } from "../components/site/Landing";
import { SiteHeader } from "../components/site/SiteHeader";
import { TokenGate } from "../components/TokenGate";
import SelfHost from "../app/self-host/page";
import type { Finding, ScanView } from "../lib/types";
import demo from "../lib/demo-data.json";

let path = "/";
const push = vi.fn();
vi.mock("next/navigation", () => ({ usePathname: () => path, useRouter: () => ({ push }) }));
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// jsdom cannot compute colours, so contrast is covered separately (tests/contrast.test.ts).
async function violations(root: Element = document.body) {
  const r = await axe.run(root, { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } });
  return r.violations.map((v) => `${v.id} (${v.impact}): ${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" | ")}`);
}
async function mount(node: React.ReactNode) {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  const root = createRoot(host);
  await act(async () => root.render(node));
  return { host, root };
}
afterEach(() => { document.body.innerHTML = ""; sessionStorage.clear(); path = "/"; vi.unstubAllGlobals(); push.mockReset(); });

describe("axe accessibility audit", () => {
  it("landing page", async () => {
    document.body.innerHTML = `<main>${renderToStaticMarkup(<Landing />)}</main>`;
    expect(await violations()).toEqual([]);
  });

  it("demo report (progress, summary, table, filters)", async () => {
    document.body.innerHTML = `<main>${renderToStaticMarkup(<DemoReport />)}</main>`;
    expect(await violations()).toEqual([]);
  });

  it("finding detail sheet, even with hostile scanner data", async () => {
    const f = { ...(demo.findings[0] as unknown as Finding), title: `<img src=x onerror=alert(1)> Title` };
    document.body.innerHTML = `<main>${renderToStaticMarkup(<FindingDetail finding={f} scan={null} onClose={() => undefined} position={{ index: 2, total: 9 }} onNext={() => undefined} />)}</main>`;
    expect(await violations()).toEqual([]);
  });

  it("token screen (client-rendered), including its error state", async () => {
    const { host } = await mount(<TokenGate><p>secret app</p></TokenGate>);
    expect(host.textContent).not.toContain("secret app"); // the wall really blocks the app
    expect(host.querySelector("label[for=token]")).not.toBeNull(); // input has a real label
    expect(host.querySelector("a[href='/sample']")).not.toBeNull(); // and a way forward without a token
    expect(await violations(host)).toEqual([]);
  });

  it("header, with the mobile menu opened", async () => {
    const { host } = await mount(<SiteHeader />);
    const btn = host.querySelector<HTMLButtonElement>(".menu-btn")!;
    expect(btn.getAttribute("aria-expanded")).toBe("false");
    expect(host.querySelector<HTMLElement>("#mobile-nav")!.hidden).toBe(true);
    await act(async () => btn.click());
    expect(btn.getAttribute("aria-expanded")).toBe("true");
    expect(host.querySelector<HTMLElement>("#mobile-nav")!.hidden).toBe(false);
    await act(async () => { document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" })); });
    expect(btn.getAttribute("aria-expanded")).toBe("false"); // Escape closes it
    expect(await violations(host)).toEqual([]);
  });

  it("header marks the current page and shows Sign out only when signed in", async () => {
    path = "/";
    const a = await mount(<SiteHeader />);
    expect(a.host.querySelector("nav a[aria-current='page']")?.textContent).toBe("Home");
    expect(a.host.textContent).not.toContain("Sign out");
    await act(async () => a.root.unmount());
    sessionStorage.setItem("bulwark.token", "x".repeat(20));
    path = "/app";
    const b = await mount(<SiteHeader />);
    expect(b.host.textContent).toContain("Sign out");
  });

  it("submit form: git mode, upload mode, and with a validation hint showing", async () => {
    const { host, root } = await mount(<SubmitForm />);
    expect(await violations(host)).toEqual([]);
    await act(async () => host.querySelector<HTMLButtonElement>("button[aria-pressed='false']")!.click()); // switch to upload
    expect(await violations(host)).toEqual([]);
    await act(async () => root.unmount());
    const b = await mount(<SubmitForm />);
    const url = b.host.querySelector<HTMLInputElement>("#url")!;
    const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
    await act(async () => { set.call(url, "not-a-url"); url.dispatchEvent(new Event("input", { bubbles: true })); });
    expect(b.host.querySelector("[role=status]")).not.toBeNull(); // the hint that fails the check below if missing
    expect(await violations(b.host)).toEqual([]);
  });

  it("recent scans: loading, empty, populated and error states", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Promise(() => undefined))); // never resolves: stays in the loading state
    const loading = await mount(<RecentScans />);
    expect(loading.host.querySelector("[aria-busy]")).not.toBeNull();
    expect(await violations(loading.host)).toEqual([]);
    await act(async () => loading.root.unmount());

    vi.stubGlobal("fetch", vi.fn(async () => json([])));
    const empty = await mount(<RecentScans />);
    await act(async () => { await Promise.resolve(); });
    expect(await violations(empty.host)).toEqual([]);
    await act(async () => empty.root.unmount());

    vi.stubGlobal("fetch", vi.fn(async () => json([
      { id: "s1", source_type: "git", source_label: "owner/repo", status: "completed", created_at: "2026-09-25T00:00:00Z", unique_findings: 3, severity_counts: { HIGH: 1, LOW: 2 } },
      { id: "s2", source_type: "git", source_label: "owner/other", status: "running", created_at: "2026-09-26T00:00:00Z", unique_findings: 0, severity_counts: {} },
    ])));
    const rows = await mount(<RecentScans />);
    await act(async () => { await Promise.resolve(); });
    expect(rows.host.querySelectorAll("tbody tr").length).toBe(2);
    expect(await violations(rows.host)).toEqual([]);
    await act(async () => rows.root.unmount());

    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("network down"); }));
    const err = await mount(<RecentScans />);
    await act(async () => { await Promise.resolve(); });
    expect(err.host.querySelector("[role=alert]")?.textContent).toContain("Cannot reach the Bulwark API");
    expect(await violations(err.host)).toEqual([]);
  });

  it("self-host page", async () => {
    document.body.innerHTML = `<main>${renderToStaticMarkup(<SelfHost />)}</main>`;
    expect(await violations()).toEqual([]);
  });
});

// Week 33/34's screens (project overview, issues table, issue detail) had no axe coverage until
// now -- added here rather than a separate file, so "does the whole app get checked" stays one
// question with one answer.
describe("axe accessibility audit — Week 33-35 screens", () => {
  const asset = { id: "a1", label: "acme/payments-api", source_type: "git", last_scanned_at: "2026-09-25T00:00:00Z", latest_scan_id: "s1", latest_scan_status: "completed" as const, open_issue_count: 1 };
  // A real multi-step taint path (plan §20.3/§28.3), not the empty-array fallback, so the axe
  // audit below actually exercises the stepper's real-data rendering (sink marker, per-step code
  // view), not just its single-step placeholder path.
  const issueFinding: Finding = {
    ...(demo.findings[0] as unknown as Finding),
    scan_id: "s1",
    taint_path: [
      { path: "routes/auth.py", line: 21, description: "username from form", is_sink: false, snippet: "20 def login():\n21     username = request.form['username']\n22     ..." },
      { path: "db/queries.py", line: 12, description: "cursor.execute(q) -- sql injection", is_sink: true, snippet: "11     q = f\"SELECT * FROM users WHERE name='{name}'\"\n12     return cursor.execute(q)\n13 " },
    ],
    issue: { id: "iss-1", state: "open", triage_status: "open", first_seen_at: "2026-09-20T00:00:00Z" },
  };

  it("projects list: loading, empty, and populated", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Promise(() => undefined)));
    const loading = await mount(<ProjectsList />);
    expect(loading.host.querySelector("[aria-busy]")).not.toBeNull();
    expect(await violations(loading.host)).toEqual([]);
    await act(async () => loading.root.unmount());

    vi.stubGlobal("fetch", vi.fn(async () => json([])));
    const empty = await mount(<ProjectsList />);
    await act(async () => { await Promise.resolve(); });
    expect(await violations(empty.host)).toEqual([]);
    await act(async () => empty.root.unmount());

    vi.stubGlobal("fetch", vi.fn(async () => json([asset])));
    const rows = await mount(<ProjectsList />);
    await act(async () => { await Promise.resolve(); });
    expect(await violations(rows.host)).toEqual([]);
  });

  it("project overview: loading and populated", async () => {
    // Real usage always renders this inside AppShell (app/app/projects/[id]/page.tsx), which
    // provides TooltipProvider for the "why it's ranked" trigger in each fix-first row.
    vi.stubGlobal("fetch", vi.fn(async () => new Promise(() => undefined)));
    const loading = await mount(<TooltipProvider><ProjectOverview assetId="a1" /></TooltipProvider>);
    expect(loading.host.querySelector("[aria-busy]")).not.toBeNull();
    expect(await violations(loading.host)).toEqual([]);
    await act(async () => loading.root.unmount());

    const overview = {
      asset, verdict_count: 1, fix_first: [issueFinding], more_at_lower_risk: 2,
      since_previous_scan: { fixed: 1, new: 1, returned: 0 },
      trend: [{ scan_id: "s1", finished_at: "2026-09-25T00:00:00Z", open_count: 3 }],
      scanned: [{ tool: "trivy", status: "ok" as const, findings: 1 }],
      latest_scan_id: "s1", latest_scan_finished_at: "2026-09-25T00:00:00Z",
    };
    vi.stubGlobal("fetch", vi.fn(async () => json(overview)));
    const rows = await mount(<TooltipProvider><ProjectOverview assetId="a1" /></TooltipProvider>);
    await act(async () => { await Promise.resolve(); });
    expect(await violations(rows.host)).toEqual([]);
  });

  it("scan comparison: picker and populated categories", async () => {
    const overview = {
      asset, verdict_count: 0, fix_first: [], more_at_lower_risk: 0,
      since_previous_scan: { fixed: 0, new: 0, returned: 0 },
      trend: [
        { scan_id: "s1", finished_at: "2026-09-01T00:00:00Z", open_count: 2 },
        { scan_id: "s2", finished_at: "2026-09-02T00:00:00Z", open_count: 1 },
      ],
      scanned: [], latest_scan_id: "s2", latest_scan_finished_at: "2026-09-02T00:00:00Z",
    };
    const comparison = {
      earlier: { scan_id: "s1", source_label: "acme/widgets", finished_at: "2026-09-01T00:00:00Z", github_pr_number: null },
      later: { scan_id: "s2", source_label: "acme/widgets", finished_at: "2026-09-02T00:00:00Z", github_pr_number: 7 },
      new: [{ id: "i-new", title: "New SQL injection", severity: "HIGH", category: "sast", path: "a.py" }],
      fixed: [], reintroduced: [],
      unchanged: [{ id: "i-same", title: "Known secret", severity: "CRITICAL", category: "secrets", path: "c.env" }],
    };
    vi.stubGlobal("fetch", vi.fn(async (url: string) => json(url.includes("/overview") ? overview : comparison)));
    const { host, root: r } = await mount(<ScanComparison assetId="a1" />);
    await act(async () => { await new Promise((res) => setTimeout(res, 50)); });
    expect(await violations(host)).toEqual([]);
    await act(async () => r.unmount());
  });

  it("issues table, populated", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json({ total: 1, limit: 200, offset: 0, items: [issueFinding] })));
    const { host } = await mount(<ModeProvider><IssuesTable assetId="a1" /></ModeProvider>);
    await act(async () => { await Promise.resolve(); });
    expect(await violations(host)).toEqual([]);
  });

  it("issue detail: loading and populated", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Promise(() => undefined)));
    const loading = await mount(<ModeProvider><IssueDetail assetId="a1" issueId="iss-1" /></ModeProvider>);
    expect(loading.host.querySelector("[aria-busy]")).not.toBeNull();
    expect(await violations(loading.host)).toEqual([]);
    await act(async () => loading.root.unmount());

    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      if (url.includes("/history")) return json([{ at: "2026-09-20T00:00:00Z", label: "First seen" }]);
      if (url.includes("/guidance")) return json({ status: 404 }, 404); // no cached guidance: a real, common case
      if (url.includes("/verified-fix")) return json({ detail: "no verified-fix run for this issue" }, 404); // none started yet
      if (url.includes("/triage-assistant")) return json({ detail: "no triage-assistant verdict for this issue yet" }, 404); // none generated yet
      return json(issueFinding);
    }));
    const rows = await mount(<ModeProvider><IssueDetail assetId="a1" issueId="iss-1" /></ModeProvider>);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(await violations(rows.host)).toEqual([]);

    // The real taint path (both hops, in order) is rendered, not the single-step placeholder,
    // and it opens on the sink -- the code view shows the dangerous call by default (plan §28.3).
    expect(rows.host.textContent).toContain("username from form");
    expect(rows.host.textContent).toContain("sql injection");
    expect(rows.host.textContent).toContain("cursor.execute(q)");

    // The triage dialogs (opened here) once had a reason textarea and an expiry date input with
    // only placeholder text and no real <label> -- axe wouldn't catch that from the closed state
    // above, only from actually opening the dialog, which is why this is its own assertion.
    // Radix's Dialog portals its content onto document.body, not into `rows.host`.
    const notARisk = [...rows.host.querySelectorAll("button")].find((b) => b.textContent === "Mark as not a risk")!;
    await act(async () => notARisk.click());
    expect(document.querySelector("label[for='triage-reason']")).not.toBeNull();
    expect(await violations()).toEqual([]);
  });

  it("live scan screen: running (with the progress banner) and partial (with the stalled-tool banner)", async () => {
    const scan = demo.scan as unknown as ScanView;
    const running: ScanView = { ...scan, status: "running", finished_at: null, tool_status: { bandit: scan.tool_status.bandit! } };
    const runningHost = await mount(<ScanReport scan={running} connection="live" version={0} />);
    expect(await violations(runningHost.host)).toEqual([]);
    await act(async () => runningHost.root.unmount());

    const partial: ScanView = { ...scan, status: "partial", tool_status: { ...scan.tool_status, trivy: { status: "timeout", findings: 0, exit_code: null, duration_seconds: 900, error: "wall-clock timeout", raw_artifact: null } } };
    const partialHost = await mount(<ScanReport scan={partial} connection="done" version={0} />);
    expect(await violations(partialHost.host)).toEqual([]);
  });
});
