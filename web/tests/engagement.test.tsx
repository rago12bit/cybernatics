// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ChecklistScreen } from "../components/ChecklistScreen";
import { EngagementScreen, dateRange } from "../components/EngagementScreen";
import { EngagementsScreen } from "../components/EngagementsScreen";
import { MentionsScreen } from "../components/MentionsScreen";
import { NotesPanel } from "../components/NotesPanel";
import { RetestPanel } from "../components/RetestPanel";
import { TagsEditor } from "../components/TagsEditor";
import type { EngagementDetail, NotesView, Retest } from "../lib/types";

const push = vi.fn();
vi.mock("next/navigation", () => ({ usePathname: () => "/app", useRouter: () => ({ push }) }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const P = "11111111-1111-4111-8111-111111111111";
const E = "22222222-2222-4222-8222-222222222222";
const I = "33333333-3333-4333-8333-333333333333";

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
type Call = { method: string; path: string; body?: unknown };
type Route = (method: string, path: string, body: unknown) => Response | undefined;

function api(route: Route) {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ method, path: u.pathname, body });
    return route(method, u.pathname, body) ?? json({}, 404);
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
const button = (host: ParentNode, text: string) =>
  Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.trim().startsWith(text)) as HTMLButtonElement;
const link = (host: ParentNode, text: string) =>
  Array.from(host.querySelectorAll("a")).find((a) => a.textContent?.trim() === text) as HTMLAnchorElement;
async function setValue(el: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement, value: string) {
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(el, value);
  await act(async () => el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? "change" : "input", { bubbles: true })));
}
const byLabel = (host: HTMLElement, text: string) => {
  const label = Array.from(host.querySelectorAll("label")).find((l) => l.textContent?.startsWith(text))!;
  return document.getElementById(label.htmlFor) as HTMLInputElement & HTMLSelectElement & HTMLTextAreaElement;
};
const dm = (iso: string) => new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "long" });
const AXE = { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } };

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  push.mockReset();
  document.body.innerHTML = "";
});

function engagement(over: Partial<EngagementDetail> = {}): EngagementDetail {
  return {
    id: E, project_id: P, project: "payments-api", name: "Q3 external pentest", engagement_type: "pentest",
    status: "in_progress", scope_targets: ["api.acme.example"], scope_routes: ["/v2/"], out_of_scope: "Admin panel, staging",
    lead: "Priya N.", testers: ["Arjun K.", "Meera S."], starts_at: "2026-09-20T00:00:00Z", ends_at: "2026-10-02T00:00:00Z",
    checklist: { id: "wstg-4.2", name: "OWASP WSTG 4.2", total: 114, done: 41, pass: 30, fail: 6, not_applicable: 5, in_progress: 2, attribution: "OWASP Foundation, CC BY-SA 4.0" },
    closed_at: null, report_generated_at: null, created_by: "token:abc", created_at: "2026-09-20T00:00:00Z",
    names: { "token:pay": "payments team" },
    findings: [
      { issue_id: "i1", title: "IDOR on GET /v2/orders/{id}", severity: "HIGH", path: "app/orders.py", state: "open", triage_status: "open",
        retest_status: null, retest_requested_by: null, priority_band: "P2", test: "Manual review", manual_finding_id: "m1",
        also_found_by: ["opengrep taint"], first_seen_at: "2026-09-21T00:00:00Z", fixed_at: null },
      { issue_id: "i2", title: "JWT accepted with alg \"none\"", severity: "HIGH", path: "app/auth.py", state: "open", triage_status: "open",
        retest_status: "requested", retest_requested_by: "token:pay", priority_band: "P1", test: "Manual review", manual_finding_id: "m2",
        also_found_by: [], first_seen_at: "2026-09-21T00:00:00Z", fixed_at: null },
      { issue_id: "i3", title: "Stack traces on /v2/auth", severity: "MEDIUM", path: "app/auth.py", state: "fixed", triage_status: "open",
        retest_status: "passed", retest_requested_by: null, priority_band: "P3", test: "ZAP baseline", manual_finding_id: null,
        also_found_by: [], first_seen_at: "2026-09-22T00:00:00Z", fixed_at: "2026-09-30T00:00:00Z" },
    ],
    tests: [
      { id: "t1", name: "Manual review", parser: "manual", findings: 9, uploads: 9, last_upload_at: null },
      { id: "t2", name: "Burp Suite", parser: "burp", findings: 14, uploads: 1, last_upload_at: null },
    ],
    ...over,
  };
}

describe("the engagement screen (plan §55.2)", () => {
  it("shows scope, people, checklist progress, findings with their correlation and retest, and tests", async () => {
    api((m, p) => (p.endsWith(`/engagements/${E}`) ? json(engagement()) : undefined));
    const host = await mount(<EngagementScreen id={E} />);
    const text = host.textContent!;
    expect(text).toContain("Q3 external pentest");
    expect(text).toContain(`In progress, ends ${dm("2026-10-02T00:00:00Z")}`);
    expect(text).toContain("api.acme.example, /v2/");
    expect(text).toContain("Admin panel, staging");
    expect(text).toContain("Arjun K., Meera S.");
    expect(text).toContain("OWASP WSTG 4.2: 41 of 114 tests done");
    expect(text).toContain("Also found by opengrep taint");
    expect(text).toContain("Retest requested by payments team");
    expect(text).toContain("Fixed: retest passed");
    expect(text).toContain("Burp Suite14 findings");
    expect(link(host, "Add a finding").getAttribute("href")).toBe(`/app/projects/${P}/findings/new?engagement=${E}`);
    expect(link(host, "Import results").getAttribute("href")).toBe(`/app/projects/${P}/import?engagement=${E}`);
    expect(link(host, "Open").getAttribute("href")).toBe(`/app/engagements/${E}/checklist`);
    const r = await axe.run(host, AXE);
    expect(r.violations.map((v) => v.id)).toEqual([]);
  });

  it("moves along the lifecycle, and closes with a summary", async () => {
    let current = engagement();
    const calls = api((m, p, b) => {
      if (p.endsWith("/close")) { current = engagement({ status: "closed", closed_at: "2026-10-02T00:00:00Z", report_generated_at: "2026-10-02T00:00:00Z" }); return json(current); }
      if (m === "PATCH") { current = { ...current, ...(b as object) }; return json(current); }
      if (p.endsWith(`/engagements/${E}`)) return json(current);
      return undefined;
    });
    const host = await mount(<EngagementScreen id={E} />);
    await act(async () => button(host, "Move to reporting").click());
    await flush();
    expect(calls.find((c) => c.method === "PATCH")!.body).toEqual({ status: "reporting" });
    expect(button(host, "Back to testing")).toBeDefined();
    await act(async () => button(host, "Close and write the report").click());
    await flush();
    const dialog = document.querySelector('[role="dialog"]') as HTMLElement;
    expect(dialog.textContent).toContain("3 findings, checklist 41 of 114 done");
    await setValue(dialog.querySelector("textarea")!, "Two highs; one fixed and retested.");
    await act(async () => button(dialog, "Close and write the report").click());
    await flush();
    expect(calls.find((c) => c.path.endsWith("/close"))!.body).toEqual({ summary: "Two highs; one fixed and retested." });
    expect(host.textContent).toContain("Closed. The report is written");
    expect(button(host, "Download Markdown")).toBeDefined();
    expect(button(host, "Reopen")).toBeDefined();
    expect(link(host, "Add a finding")).toBeUndefined();
  });

  it("words the dates by status", () => {
    expect(dateRange({ status: "planned", starts_at: "2026-10-10T00:00:00Z", ends_at: null, closed_at: null })).toBe(`starts ${dm("2026-10-10T00:00:00Z")}`);
    expect(dateRange({ status: "closed", starts_at: null, ends_at: null, closed_at: "2026-10-02T00:00:00Z" })).toBe(`closed ${dm("2026-10-02T00:00:00Z")}`);
    expect(dateRange({ status: "in_progress", starts_at: null, ends_at: null, closed_at: null })).toBe("no end date");
  });
});

describe("creating an engagement", () => {
  it("sends scope, people, dates and the checklist, then opens it", async () => {
    const calls = api((m, p) => {
      if (p.endsWith("/v2/checklists")) return json([{ id: "wstg-4.2", name: "OWASP WSTG 4.2", items: 114, source: "", attribution: "" }]);
      if (m === "POST") return json({ ...engagement(), id: E }, 201);
      if (p.endsWith("/engagements")) return json([]);
      return undefined;
    });
    const host = await mount(<EngagementsScreen assetId={P} />);
    expect(host.textContent).toContain("No engagements yet.");
    await act(async () => button(host, "New engagement").click());
    await flush();
    await setValue(byLabel(host, "Name"), "Q3 external pentest");
    await setValue(byLabel(host, "In scope: targets"), "api.acme.example\nshop.acme.example");
    await setValue(byLabel(host, "Testers"), "Arjun K., Meera S.");
    await setValue(byLabel(host, "Ends"), "2026-10-02");
    await setValue(byLabel(host, "Checklist"), "wstg-4.2");
    await act(async () => button(host, "Create engagement").click());
    await flush();
    const post = calls.find((c) => c.method === "POST")!;
    expect(post.body).toMatchObject({ name: "Q3 external pentest", engagement_type: "pentest", scope_targets: ["api.acme.example", "shop.acme.example"],
      testers: ["Arjun K.", "Meera S."], ends_at: "2026-10-02T00:00:00Z", checklist: "wstg-4.2" });
    expect(push).toHaveBeenCalledWith(`/app/engagements/${E}`);
  });
});

describe("the checklist", () => {
  it("records a result per item and filters to what failed", async () => {
    const items = [
      { id: "WSTG-INFO-01", group: "WSTG-INFO Information Gathering", title: "Search engine reconnaissance", level: null, cwe: null, reference: "https://owasp.org/x", status: "pass", note: null, updated_by: null, updated_at: null },
      { id: "WSTG-ATHZ-04", group: "WSTG-ATHZ Authorization Testing", title: "Testing for IDOR", level: null, cwe: null, reference: null, status: null, note: null, updated_by: null, updated_at: null },
    ];
    const summary = { id: "wstg-4.2", name: "OWASP WSTG 4.2", total: 2, done: 1, pass: 1, fail: 0, not_applicable: 0, in_progress: 0, attribution: "OWASP Foundation, CC BY-SA 4.0" };
    const calls = api((m, p) => {
      if (m === "PUT") return json({ ...summary, done: 2, fail: 1 });
      if (p.endsWith("/checklist")) return json({ summary, items });
      if (p.endsWith(`/engagements/${E}`)) return json(engagement());
      return undefined;
    });
    const host = await mount(<ChecklistScreen id={E} />);
    expect(host.textContent).toContain("1 of 2 done: 1 passed");
    const sel = host.querySelector('select[aria-label="WSTG-ATHZ-04 result"]') as HTMLSelectElement;
    await setValue(sel, "fail");
    await flush();
    const put = calls.find((c) => c.method === "PUT")!;
    expect(put.path).toBe(`/v2/engagements/${E}/checklist/WSTG-ATHZ-04`);
    expect(put.body).toEqual({ status: "fail", note: null });
    expect(host.textContent).toContain("2 of 2 done");
    await act(async () => button(host, "Failed").click());
    expect(host.querySelectorAll(".ds-eng-checks li").length).toBe(1);
    expect(host.textContent).toContain("OWASP Foundation, CC BY-SA 4.0");
    const r = await axe.run(host, AXE);
    expect(r.violations.map((v) => v.id)).toEqual([]);
  });
});

function retest(over: Partial<Retest> = {}): Retest {
  return {
    issue_id: I, state: "open", status: null, requested_at: null, requested_by: null, note: null, decided_at: null, decided_by: null,
    targeted: { available: true, kind: "rule", tool: "opengrep", rule: "python.sqli", location: "app/db.py", reason: null },
    runs: [], names: { "token:pri": "Priya N." }, ...over,
  };
}

describe("the retest panel (plan §43.3)", () => {
  it("marks it ready, then a tester decides; reproducing needs a note", async () => {
    let current = retest();
    const calls = api((m, p, b) => {
      if (p.endsWith("/retest/run")) { current = retest({ status: "requested", runs: [{ id: "r1", kind: "rule", tool: "opengrep", rule: "python.sqli", location: "app/db.py", status: "done", result: "gone", detail: "opengrep rule python.sqli no longer fires on app/db.py.", requested_by: null, created_at: "", finished_at: "" }] }); return json(current, 202); }
      if (m === "POST") {
        const a = (b as { action: string }).action;
        current = a === "request" ? retest({ status: "requested", requested_by: "token:pri", requested_at: "2026-10-01T00:00:00Z", note: "Fixed in #412" }) : retest({ status: "failed", note: (b as { note: string }).note });
        return json(current);
      }
      return p.endsWith("/retest") ? json(current) : undefined;
    });
    const changed = vi.fn();
    const host = await mount(<RetestPanel issueId={I} onChange={changed} />);
    expect(host.textContent).toContain("No retest requested.");
    expect(host.textContent).toContain("Targeted retest: rule python.sqli (opengrep) against app/db.py only.");
    await setValue(host.querySelector("textarea")!, "Fixed in #412");
    await act(async () => button(host, "Ready for retest").click());
    await flush();
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ action: "request", note: "Fixed in #412" });
    expect(host.textContent).toContain("Ready for retest: asked by Priya N.");
    expect(button(host, "Reproduced").disabled).toBe(true);
    await setValue(host.querySelector("textarea")!, "Still returns other users' orders");
    await act(async () => button(host, "Reproduced").click());
    await flush();
    expect(calls.filter((c) => c.method === "POST").at(-1)!.body).toEqual({ action: "reproduced", note: "Still returns other users' orders" });
    expect(host.textContent).toContain("Retest failed");
    await act(async () => button(host, "Run the targeted retest").click());
    await flush();
    expect(host.textContent).toContain("Last targeted retest: opengrep rule python.sqli no longer fires on app/db.py.");
    expect(changed).toHaveBeenCalled();
  });
});

function notes(over: Partial<NotesView> = {}): NotesView {
  return {
    you: "token:pri",
    names: { "token:pri": "Priya N.", "token:arj": "Arjun K." },
    notes: [
      { id: "n1", issue_id: I, parent_id: null, body: "<img src=x onerror=alert(1)> @arjunk please retest", author: "token:pri", mentions: ["token:arj"],
        created_at: "2026-10-01T10:00:00Z", edited_at: null, deleted: false, files: [{ id: "f1", file_name: "capture.html", sniffed_type: "text/html", active_content: true, size_bytes: 2048, encrypted: true }] },
      { id: "n2", issue_id: I, parent_id: "n1", body: "On it.", author: "token:arj", mentions: [], created_at: "2026-10-01T11:00:00Z", edited_at: null, deleted: false, files: [] },
    ],
    ...over,
  };
}

describe("notes (plan §49)", () => {
  it("shows bodies as text, marks mentions, and offers people to mention", async () => {
    const calls = api((m, p, b) => {
      if (p.endsWith("/v2/people")) return json([{ actor: "token:arj", name: "Arjun K.", handle: "arjunk" }, { actor: "token:pri", name: "Priya N.", handle: "priyan" }]);
      if (m === "POST" && p.endsWith("/notes")) return json(notes({ notes: [...notes().notes, { ...notes().notes[1]!, id: "n3", parent_id: null, author: "token:pri", body: (b as { body: string }).body }] }), 201);
      if (p.endsWith("/notes")) return json(notes());
      return undefined;
    });
    const host = await mount(<NotesPanel issueId={I} />);
    expect(host.querySelector(".ds-notes img")).toBeNull();
    expect(host.textContent).toContain("<img src=x onerror=alert(1)>");
    expect(host.querySelector(".ds-note-mention")!.textContent).toBe("@arjunk");
    expect(host.querySelector(".ds-note-reply")!.textContent).toContain("On it.");
    expect(host.textContent).toContain("can contain script: download only");
    // only my own note can be edited
    const own = host.querySelectorAll(".ds-note")[0]!;
    const theirs = host.querySelectorAll(".ds-note")[1]!;
    expect(button(own, "Edit")).toBeDefined();
    expect(button(theirs, "Edit")).toBeUndefined();
    const box = byLabel(host, "Add a note");
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!.call(box, "cc @arj");
    box.setSelectionRange(7, 7);
    await act(async () => box.dispatchEvent(new Event("input", { bubbles: true })));
    const option = host.querySelector('[role="listbox"] button') as HTMLButtonElement;
    expect(option.textContent).toContain("Arjun K.");
    await act(async () => option.click());
    expect(box.value).toBe("cc @arjunk ");
    await act(async () => button(host, "Add note").click());
    await flush();
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ body: "cc @arjunk ", parent_id: null });
    const r = await axe.run(host, AXE);
    expect(r.violations.map((v) => v.id)).toEqual([]);
  });
});

describe("tags (plan §49)", () => {
  it("shows inherited tags with their source and edits only the issue's own", async () => {
    const calls = api((m, p, b) => {
      if (m === "PUT") return json({ own: (b as { tags: string[] }).tags, inherited: [{ name: "payments", from: "project", source: "payments-api" }] });
      if (p.endsWith("/tags")) return json({ own: ["idor"], inherited: [{ name: "payments", from: "project", source: "payments-api" }, { name: "pci-dss", from: "portfolio", source: "Payments" }] });
      return undefined;
    });
    const host = await mount(<TagsEditor kind="issue" id={I} />);
    expect(host.textContent).toContain("Inherited: payments from payments-api (project), pci-dss from Payments (portfolio)");
    expect(host.querySelector('[aria-label="Remove tag payments"]')).toBeNull();
    await setValue(host.querySelector('input[aria-label="Add a tag to this issue"]')!, "tier-1");
    await act(async () => button(host, "Add").click());
    await flush();
    expect(calls.find((c) => c.method === "PUT")!.body).toEqual({ tags: ["idor", "tier-1"] });
  });
});

describe("mentions", () => {
  it("lists notes that mention you, with the issue", async () => {
    api((m, p) => (p.endsWith("/v2/mentions") ? json({ mentions: [{ note: notes().notes[0], issue_title: "SQL injection in /orders", project_id: P }], names: { "token:pri": "Priya N." } }) : undefined));
    const host = await mount(<MentionsScreen />);
    expect(host.textContent).toContain("Priya N. on SQL injection in /orders");
    expect(link(host, "SQL injection in /orders").getAttribute("href")).toBe(`/app/projects/${P}/issues/${I}`);
  });
});
