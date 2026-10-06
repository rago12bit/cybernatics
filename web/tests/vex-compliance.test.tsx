// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AdvisoryScreen } from "../components/AdvisoryScreen";
import { AsvsScreen } from "../components/AsvsScreen";
import { EvidenceScreen } from "../components/EvidenceScreen";
import { ProjectVexScreen } from "../components/ProjectVexScreen";
import type { AdvisoryImpact, AdvisoryUse, AsvsBenchmark, EvidencePack, ProjectVex, VexStatement } from "../lib/types";
import { JUSTIFICATIONS, justificationLabel } from "../lib/vex";

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
async function mount(node: React.ReactNode) {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(node));
  await flush();
  return host;
}
const button = (host: HTMLElement, text: string) =>
  [...host.querySelectorAll("button")].find((b) => b.textContent?.includes(text)) as HTMLButtonElement;

const EVIDENCE = {
  kind: "symbols" as const, label: "Vulnerable functions not called (Go)",
  summary: "Application code does not call Parse, ParseFragment in golang.org/x/net/html. Checked 12 Go files.",
  details: {}, caveats: ["Code inside other dependencies is not analysed."],
};
const statement = (over: Partial<VexStatement> = {}): VexStatement => ({
  id: "s1", asset_id: "p2", vuln_key: "CVE-2021-33194", library: "golang.org/x/net", ecosystem: "go",
  version: "v0.0.0-2021", status: "not_affected", justification: "vulnerable_code_not_in_execute_path",
  impact_statement: EVIDENCE.summary, evidence: EVIDENCE, state: "proposed", proposed_by: "token:a",
  proposed_at: "2026-10-06T08:00:00Z", decided_by: null, decided_at: null, note: null, ...over,
});
const use = (over: Partial<AdvisoryUse>): AdvisoryUse => ({
  project_id: "p1", project: "calls-parse", portfolio: null, library: "golang.org/x/net", ecosystem: "go",
  purl: "pkg:golang/golang.org/x/net", version: "v0.0.0-2021", fixed_version: "0.0.0-20210520", certain: true,
  resolved_at: null, first_seen_at: "2026-10-06T08:00:00Z", relation: "direct", paths: ["go.mod"], reachable: true,
  reachable_reason: "Imported by application code (main.go)", exposure: "internet", owner: null, issues: [],
  vex: { draftable: false, evidence: null, summary: "Application code uses html.Parse (main.go:6)", uses_code: true, where: "main.go:6", statement: null },
  ...over,
});
const IMPACT = (uses: AdvisoryUse[], draftable: number): AdvisoryImpact => ({
  vuln_key: "CVE-2021-33194", ids: ["GO-2021-0238"], aliases: [], cves: ["CVE-2021-33194"], summary: "Infinite loop in ParseFragment",
  details: "", severity: "HIGH", cvss: 7.5, cvss_vector: "", malicious: false, kev: null, published: null,
  modified: "2026-01-01T00:00:00Z", references: [], withdrawn: false, state: "new", first_seen_at: "2026-10-06T07:00:00Z",
  uses, no_longer_affected: [],
  summary_counts: { projects: uses.length, portfolios: 0, imported_by_app: 2, internet_facing: 2, uncertain: 0, with_fix: 2, with_issues: 0, vex_draftable: draftable },
});

describe("VEX", () => {
  it("names every OpenVEX justification in plain words", () => {
    expect(JUSTIFICATIONS.map((j) => j.value)).toEqual([
      "component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
      "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist",
    ]);
    expect(justificationLabel("vulnerable_code_not_in_execute_path")).toBe("The vulnerable code is never executed");
    expect(justificationLabel("nope")).toBeNull();
  });

  it("drafts on the advisory page, then a person confirms each proposal with its evidence", async () => {
    const calls: string[] = [];
    let drafted = false;
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      const u = new URL(String(url));
      calls.push(`${init?.method ?? "GET"} ${u.pathname}`);
      if (u.pathname === "/v2/advisories/CVE-2021-33194/vex-drafts") { drafted = true; return json({ proposed: 1, already: 0, skipped: { "Application code uses html.Parse": 1 }, ids: ["s1"] }); }
      if (u.pathname === "/v2/vex/s1/confirm") return json(statement({ state: "confirmed" }));
      const other = use({ project_id: "p2", project: "tokenizer-only",
        vex: { draftable: !drafted, evidence: EVIDENCE, summary: EVIDENCE.summary, uses_code: false, where: "", statement: drafted ? statement() : null } });
      return json(IMPACT([use({}), other], drafted ? 0 : 1));
    }));
    const host = await mount(<AdvisoryScreen vulnKey="CVE-2021-33194" />);
    expect(host.textContent).toContain("main.go:6");
    expect(host.textContent).toContain("Not the vulnerable functions");
    expect(host.textContent).toContain("Can be drafted");
    const draft = button(host, "Draft VEX for the other 1 use");
    expect(host.textContent).not.toContain("Draft VEX for all");
    expect(draft.disabled).toBe(false);
    await act(async () => draft.click());
    await flush();
    expect(calls).toContain("POST /v2/advisories/CVE-2021-33194/vex-drafts");
    expect(host.textContent).toContain("1 proposal to review below");
    expect(host.textContent).toContain("Not proposed: 1 (Application code uses html.Parse)");
    expect(host.textContent).toContain("VEX proposals to review");
    expect(host.textContent).toContain("Code inside other dependencies is not analysed.");
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    await act(async () => button(host, "Confirm").click());
    await flush();
    expect(calls).toContain("POST /v2/vex/s1/confirm");
  });

  it("shows what a project's VEX says and downloads it", async () => {
    const v: ProjectVex = {
      project_id: "p2", project: "tokenizer-only", counts: { not_affected: 1, affected: 1 },
      statements: [statement({ state: "confirmed", decided_by: "token:meera", note: "reviewed" })],
      exported: [
        { vuln_key: "CVE-2021-33194", library: "golang.org/x/net", version: "v0.0.0-2021", purl: "pkg:golang/golang.org/x/net@v0.0.0-2021",
          status: "not_affected", justification: "vulnerable_code_not_in_execute_path", basis: "vex", impact_statement: "x", action_statement: null },
        { vuln_key: "CVE-2021-44228", library: "org.apache.logging.log4j:log4j-core", version: "2.14.1", purl: "pkg:maven/x@2.14.1",
          status: "affected", justification: null, basis: "match", impact_statement: null, action_statement: "Upgrade to 2.15.0 or later." },
      ],
    };
    const fetched: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      const u = new URL(String(url));
      fetched.push(u.pathname);
      if (u.pathname.endsWith("/vex/openvex")) return new Response("{}", { headers: { "Content-Disposition": 'attachment; filename="p.openvex.json"' } });
      return json(v);
    }));
    URL.createObjectURL = vi.fn(() => "blob:x");
    URL.revokeObjectURL = vi.fn();
    const host = await mount(<ProjectVexScreen assetId="p2" />);
    expect(host.textContent).toContain("1 not affected, 1 affected");
    expect(host.textContent).toContain("The vulnerable code is never executed");
    expect(host.textContent).toContain("from confirmed VEX statement");
    expect(host.textContent).toContain("Upgrade to 2.15.0 or later.");
    expect(host.textContent).toContain("confirmed by token:meera");
    expect(button(host, "Withdraw")).toBeTruthy();
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    await act(async () => button(host, "Download OpenVEX").click());
    await flush();
    expect(fetched).toContain("/v2/projects/p2/vex/openvex");
  });
});

describe("compliance", () => {
  it("shows the ASVS checklist, where only a person marks a requirement met", async () => {
    const b: AsvsBenchmark = {
      project_id: "p1", project: "payments-api", level: 2, counts: { issues_open: 1, met: 1, not_assessed: 1 },
      disclaimer: "A requirement is met only when a person says so.",
      framework: { id: "asvs-4.0.3", name: "OWASP ASVS 4.0.3", source: { url: "https://github.com/OWASP/ASVS/tree/v4.0.3" }, mapping_version: 1 },
      requirements: [
        { id: "V5.3.4", group: "V5", title: "Verify that data selection or database queries use parameterized queries.", level: 1, cwe: "CWE-89",
          status: "met", source: "person", issues: 1, issue_ids: ["i1"], assessment: null, note: "ORM only", links: [], set_by: "token:a",
          set_at: "2026-10-06T08:00:00Z", conflict: true },
        { id: "V3.2.1", group: "V3", title: "Verify the application generates a new session token on user authentication.", level: 1, cwe: "CWE-384",
          status: "issues_open", source: "issues", issues: 2, issue_ids: ["i2"], assessment: null, note: "", links: [], set_by: null, set_at: null, conflict: false },
        { id: "V2.1.1", group: "V2", title: "Verify that user set passwords are at least 12 characters in length.", level: 1, cwe: "CWE-521",
          status: "not_assessed", source: "", issues: 0, issue_ids: [], assessment: null, note: "", links: [], set_by: null, set_at: null, conflict: false },
      ],
    };
    const puts: unknown[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      if (init?.method === "PUT") { puts.push(JSON.parse(String(init.body))); return json({ requirement: "V2.1.1", status: "not_applicable" }); }
      return json(b);
    }));
    const host = await mount(<AsvsScreen assetId="p1" />);
    expect(host.textContent).toContain("contradicted by the evidence");
    expect(host.textContent).toContain("2 open Issues");
    expect(host.textContent).toContain("Not assessed");
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    const set = [...host.querySelectorAll("button")].filter((x) => x.textContent === "Set")[2]!;
    await act(async () => set.click());
    const select = host.querySelector("tr.ds-cmp-editor-row select") as HTMLSelectElement;
    const note = host.querySelector("tr.ds-cmp-editor-row textarea") as HTMLTextAreaElement;
    await act(async () => {
      select.value = "not_applicable";
      select.dispatchEvent(new Event("change", { bubbles: true }));
      const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!;
      setter.call(note, "SSO only: no passwords");
      note.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await act(async () => button(host, "Save").click());
    await flush();
    expect(puts).toEqual([{ status: "not_applicable", note: "SSO only: no passwords", links: [] }]);
  });

  it("previews, generates and lists evidence packs", async () => {
    const summary = {
      projects: 3, scanned: 2, sla: { met: 4, missed: 1, open_past_deadline: 1, exempt: 0, adherence: 0.6667 },
      risk_acceptances: 2, open_issues: 9, vex_confirmed: 1, engagements: 1,
      audit: { entries: 40, disclosed: 12, ok: true, anchored_at: [40], linked_only: 0 }, frameworks: ["pci-dss-4.0-req6"],
    };
    const pack: EvidencePack = { id: "e1", period_start: "2026-07-01", period_end: "2026-09-30", frameworks: ["pci-dss-4.0-req6"],
      summary, sha256: "ab".repeat(32), signed: false, size: 40960, created_by: "token:a", created_at: "2026-10-06T08:00:00Z" };
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      const u = new URL(String(url));
      calls.push(`${init?.method ?? "GET"} ${u.pathname}`);
      if (u.pathname === "/v2/compliance/frameworks") return json([{ id: "pci-dss-4.0-req6", name: "PCI DSS v4.0, Requirement 6", framework_version: "4.0", source: {}, mapping_version: 1, mapping_date: "2026-10-06", controls: 12 }]);
      if (u.pathname === "/v2/evidence-packs/preview") return json({ ...summary, signing: false, disclaimer: "x" });
      if (u.pathname === "/v2/evidence-packs" && init?.method === "POST") return json(pack, 201);
      if (u.pathname === "/v2/evidence-packs") return json([]);
      return json({}, 404);
    }));
    const host = await mount(<EvidenceScreen />);
    expect(host.textContent).toContain("not a certification");
    expect(button(host, "Generate the pack").disabled).toBe(true);
    await act(async () => button(host, "See what will be included").click());
    await flush();
    expect(host.textContent).toContain("SLA adherence 66.7%");
    expect(host.textContent).toContain("anchored by Rekor checkpoints at entries 40");
    expect(host.textContent).toContain("the pack will be marked unsigned");
    expect((await axe.run(host, AXE)).violations).toEqual([]);
    await act(async () => button(host, "Generate the pack").click());
    await flush();
    expect(calls).toContain("POST /v2/evidence-packs");
    expect(host.textContent).toContain("2026-07-01 to 2026-09-30");
    expect(host.textContent).toContain("unsigned");
  });
});
