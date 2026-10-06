// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AutomationScreen, automationVerdict, outcomeSummary } from "../components/AutomationScreen";
import { OwnerPanel } from "../components/OwnerPanel";
import type { IssueOwner, Rule, RuleRun } from "../lib/types";

const push = vi.fn();
vi.mock("next/navigation", () => ({ usePathname: () => "/app", useRouter: () => ({ push }) }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const R = "44444444-4444-4444-8444-444444444444";
const RUN = "55555555-5555-4555-8555-555555555555";
const I = "33333333-3333-4333-8333-333333333333";
const P = "11111111-1111-4111-8111-111111111111";

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
type Call = { method: string; path: string; search: string; body?: unknown };
type Route = (method: string, path: string, body: unknown, search: string) => Response | undefined;

function api(route: Route) {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ method, path: u.pathname, search: u.search, body });
    return route(method, u.pathname, body, u.search) ?? json({}, 404);
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
async function setValue(el: HTMLSelectElement | HTMLInputElement | HTMLTextAreaElement, value: string) {
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(el, value);
  await act(async () => el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? "change" : "input", { bubbles: true })));
}
const byLabel = (host: HTMLElement, text: string) => {
  const label = Array.from(host.querySelectorAll("label")).find((l) => l.textContent?.startsWith(text))!;
  return document.getElementById(label.htmlFor) as HTMLInputElement & HTMLSelectElement & HTMLTextAreaElement;
};
const AXE = { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } };

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  push.mockReset();
  document.body.innerHTML = "";
});

export function rule(over: Partial<Rule> = {}): Rule {
  return {
    id: R, name: "Critical payments to on-call", description: null, project_id: null, project_name: null,
    enabled: true, trigger: "issue.created", trigger_label: "An issue is found", trigger_params: {},
    condition: 'input.issue.priority_band == "P1"', actions: [{ type: "assign", to: "priyan" }],
    rego: "package bulwark.rule", confirm_over: 25, version: 2, template: null,
    summary: ["WHEN an issue is found in any project", 'IF input.issue.priority_band == "P1"', "THEN assign to @priyan"],
    created_by: "token:abc", created_at: "2026-10-06T08:00:00Z", updated_by: "token:abc",
    updated_at: "2026-10-06T08:00:00Z", last_fired_at: null, names: {}, ...over,
  };
}

export function run(over: Partial<RuleRun> = {}): RuleRun {
  return {
    id: RUN, rule_id: R, rule_name: "Critical payments to on-call", rule_version: 2, trigger: "issue.created",
    cause: "scan:x", cause_label: "a scan", depth: 0, status: "applied", subject_ids: [I],
    subjects: [{ id: I, text: "SQL injection", project: "payments-api", title: "SQL injection", severity: "CRITICAL", priority_band: "P1", asset_id: P }],
    results: [{ action: "assign", subject: I, outcome: "changed", detail: "@priyan" }],
    error: null, created_at: "2026-10-06T09:00:00Z", decided_by: null, decided_at: null, names: {}, ...over,
  };
}

describe("automation screen", () => {
  it("puts held runs first, applies one, and is accessible", async () => {
    let held = [run({ status: "held", subject_ids: [I, "b", "c"], results: [] })];
    const calls = api((m, p, _b, q) => {
      if (p === "/v2/rules") return json([rule(), rule({ id: "off", name: "Quiet projects", enabled: false })]);
      if (p === "/v2/rule-runs" && q.includes("status=held")) return json(held);
      if (p === "/v2/rule-runs") return json([run(), run({ id: "f", status: "failed", results: [], error: "condition: bad" }),
                                              run({ id: "d", status: "depth_limited", depth: 3, results: [], subjects: [], subject_ids: [] })]);
      if (m === "POST" && p === `/v2/rule-runs/${RUN}/confirm`) {
        held = [];
        return json(run({ status: "confirmed" }));
      }
      return undefined;
    });
    const host = await mount(<AutomationScreen />);
    expect(host.querySelector(".ds-au-verdict")?.textContent).toBe("1 run is waiting for an Admin to confirm.");
    const heading = Array.from(host.querySelectorAll("h2")).map((h) => h.textContent);
    expect(heading).toEqual(["Waiting for confirmation", "Rules", "Run history"]);
    expect(host.textContent).toContain("would act on 3 issues from a scan");
    expect(host.textContent).toContain("…and 2 more");
    expect(host.querySelectorAll(".ds-au-rule")[1]!.className).toContain("ds-au-off");
    expect(host.textContent).toContain("Stopped: chain too deep");
    expect(host.textContent).toContain("chain 3");
    expect(host.textContent).toContain("condition: bad");
    const results = await axe.run(host, AXE);
    expect(results.violations.map((v) => v.id)).toEqual([]);
    await act(async () => button(host, "Apply to all 3").click());
    await flush();
    expect(calls.some((c) => c.method === "POST" && c.path === `/v2/rule-runs/${RUN}/confirm`)).toBe(true);
    expect(host.querySelector(".ds-au-verdict")?.textContent).toBe("1 of 2 rules on. Nothing is waiting.");
  });

  it("tests a rule and shows the server's refusal when you are not an Admin", async () => {
    api((m, p) => {
      if (p === "/v2/rules") return json([rule()]);
      if (p === "/v2/rule-runs") return json([]);
      if (m === "POST" && p === `/v2/rules/${R}/test`) {
        return json({ subject: "issue", matched: 37, runs: 4, would_hold: 1, checked: 120, window_days: 7, sample: [],
                      note: "Checked against each issue as it is now.", sentence: "This rule would have matched 37 issues in the last 7 days." });
      }
      if (m === "PUT" && p === `/v2/rules/${R}/enabled`) return json({ detail: "this token does not have the 'rules:write' scope" }, 403);
      return undefined;
    });
    const host = await mount(<AutomationScreen />);
    await act(async () => button(host, "Test this rule").click());
    await flush();
    expect(host.querySelector(".ds-au-dry")?.textContent).toContain("would have matched 37 issues in the last 7 days");
    await act(async () => button(host, "Turn off").click());
    await flush();
    expect(host.querySelector("[role=alert]")?.textContent).toContain("rules:write");
  });

  it("says what a run did, in words", () => {
    expect(outcomeSummary(run())).toBe("1 change.");
    expect(outcomeSummary(run({ results: [
      { action: "assign", subject: I, outcome: "failed", detail: "Nobody in this organization is @x." },
      { action: "tag", subject: I, outcome: "skipped", detail: "already" },
    ] }))).toBe("0 changes, 1 failed (Nobody in this organization is @x.), 1 skipped (already).");
    expect(automationVerdict([], [])).toBe("No rules yet: nothing runs on its own.");
  });
});

describe("owner panel", () => {
  const owner = (over: Partial<IssueOwner> = {}): IssueOwner => ({
    assignee: null, assignee_name: null, assignee_handle: null, assigned_at: null,
    priority_override: null, priority_override_by: null, computed_band: "P3", names: {}, ...over,
  });

  it("assigns, sets a band by hand, and names the rule that did it", async () => {
    let current = owner({ priority_override: "P1", priority_override_by: `rule:${R}`, names: { [`rule:${R}`]: "the rule “Critical payments”" } });
    const calls = api((m, p, b) => {
      if (p === "/v2/people") return json([{ actor: "token:a", name: "Priya N.", handle: "priyan" }]);
      if (p === `/v2/issues/${I}/assignee` && m === "GET") return json(current);
      if (p === `/v2/issues/${I}/assignee` && m === "PUT") {
        current = { ...current, assignee: "token:a", assignee_name: "Priya N.", assignee_handle: (b as { to: string }).to };
        return json(current);
      }
      if (p === `/v2/issues/${I}/priority`) {
        current = { ...current, priority_override: (b as { band: string | null }).band, priority_override_by: null };
        return json(current);
      }
      return undefined;
    });
    const host = await mount(<OwnerPanel issueId={I} />);
    expect(host.textContent).toContain("Set by the rule “Critical payments”; computed P3.");
    await setValue(byLabel(host, "Assigned to"), "priyan");
    await flush();
    expect(calls.find((c) => c.method === "PUT" && c.path.endsWith("/assignee"))?.body).toEqual({ to: "priyan" });
    expect(byLabel(host, "Assigned to").value).toBe("priyan");
    await setValue(byLabel(host, "Priority"), "");
    await flush();
    expect(calls.find((c) => c.path.endsWith("/priority"))?.body).toEqual({ band: null });
    expect(host.textContent).not.toContain("Set by");
    const results = await axe.run(host, AXE);
    expect(results.violations.map((v) => v.id)).toEqual([]);
  });

  it("stays away when the response is not what it expects", async () => {
    api((_m, p) => (p.endsWith("/assignee") ? json({ unexpected: true }) : json([])));
    const host = await mount(<OwnerPanel issueId={I} />);
    expect(host.textContent).toBe("");
  });
});
