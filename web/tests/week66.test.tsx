// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { InboxScreen, inboxVerdict } from "../components/InboxScreen";
import { NotificationSettings } from "../components/NotificationSettings";
import { RuleEditor, fromRego, moduleFor, toRego } from "../components/RuleEditor";
import { TicketPanel, WatchButton } from "../components/TicketPanel";
import { TicketSettingsScreen } from "../components/TicketSettingsScreen";
import type { Inbox, IssueTicket, NotificationPrefsView, RulesCatalogue } from "../lib/types";

const push = vi.fn();
vi.mock("next/navigation", () => ({ usePathname: () => "/app", useRouter: () => ({ push }) }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const I = "33333333-3333-4333-8333-333333333333";
const P = "11111111-1111-4111-8111-111111111111";
const G = "66666666-6666-4666-8666-666666666666";

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
const byAria = (host: HTMLElement, label: string) => host.querySelector(`[aria-label="${label}"]`) as HTMLInputElement & HTMLSelectElement;
const AXE = { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } };

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  push.mockReset();
  document.body.innerHTML = "";
});

const CAT: RulesCatalogue = {
  triggers: [
    { key: "issue.created", label: "An issue is found", subject: "issue", params: [], help: "" },
    { key: "project.quiet", label: "No scan for N days", subject: "project", params: ["days"], help: "" },
    { key: "schedule", label: "On a schedule", subject: "issue", params: ["every", "hour", "weekday"], help: "" },
  ],
  actions: [
    { key: "assign", label: "Assign to", subjects: ["issue"], params: ["to"], help: "" },
    { key: "set_priority", label: "Set priority", subjects: ["issue"], params: ["band"], help: "" },
    { key: "tag", label: "Add tags", subjects: ["issue"], params: ["tags"], help: "" },
    { key: "notify", label: "Notify", subjects: ["issue", "project"], params: ["message", "people"], help: "" },
  ],
  fields: {
    issue: [{ path: "input.issue.severity", help: "CRITICAL…" }, { path: "input.issue.tags", help: "list" },
            { path: "input.issue.in_cisa_kev", help: "true or false" }, { path: "input.issue.age_days", help: "days" }],
    project: [{ path: "input.project.tags", help: "list" }],
    event: [{ path: "input.event.type", help: "" }],
  },
  limits: { max_actions: 8, max_depth: 3, default_confirm_over: 25, max_confirm_over: 1000 },
};

describe("the condition builder writes Rego and reads it back", () => {
  it("round-trips what it writes, and refuses what it did not", () => {
    const rows = [
      { path: "input.issue.severity", op: "==" as const, value: "CRITICAL" },
      { path: "input.issue.tags", op: "contains" as const, value: "payments" },
      { path: "input.issue.in_cisa_kev", op: "==" as const, value: "true" },
      { path: "input.issue.age_days", op: ">=" as const, value: "30" },
      { path: "input.issue.assignee", op: "unset" as const, value: "" },
      { path: "input.issue.title", op: "==" as const, value: 'say "hi"\\' },
    ];
    const rego = toRego(rows);
    expect(rego).toBe([
      'input.issue.severity == "CRITICAL"', 'input.issue.tags[_] == "payments"', "input.issue.in_cisa_kev == true",
      "input.issue.age_days >= 30", "not input.issue.assignee", 'input.issue.title == "say \\"hi\\"\\\\"',
    ].join("\n"));
    expect(fromRego(rego)).toEqual(rows.map((r) => (r.path.endsWith("kev") ? { ...r, value: "true" } : r)));
    expect(fromRego('input.issue.severity in {"HIGH", "CRITICAL"}')).toBeNull();
    expect(fromRego("count(input.issue.cwe) > 2")).toBeNull();
    expect(moduleFor("")).toContain("match if {\n  true\n}");
  });
});

describe("rule editor", () => {
  it("opens a template, fills it in, tests it, and saves it", async () => {
    const calls = api((m, p, b) => {
      if (p === "/v2/rules/catalogue") return json(CAT);
      if (p === "/assets") return json([{ id: P, label: "payments-api" }]);
      if (p === "/v2/people") return json([{ actor: "token:a", name: "Priya N.", handle: "priyan" }]);
      if (p === "/v2/rules/templates") return json([{ key: "critical-to-oncall", name: "Critical to on-call", description: "", needs: ["actions.0.to"],
        draft: { name: "Critical to on-call", template: "critical-to-oncall", trigger: "issue.created", condition: 'input.issue.severity == "CRITICAL"',
                 actions: [{ type: "assign", to: "" }, { type: "set_priority", band: "P1" }] } }]);
      if (m === "POST" && p === "/v2/rules/test") {
        if (!(b as { actions: { to?: string }[] }).actions[0]!.to) return json({ detail: { field: "actions.0.to", message: "Name a person by their @handle." } }, 422);
        return json({ subject: "issue", matched: 4, runs: 2, would_hold: 0, checked: 9, window_days: 7, note: "as it is now",
                      sample: [{ id: "x", text: "CRITICAL SQL injection (payments-api)", project: "payments-api" }],
                      sentence: "This rule would have matched 4 issues in the last 7 days." });
      }
      if (m === "POST" && p === "/v2/rules") return json({ id: "new-rule" }, 201);
      return undefined;
    });
    const host = await mount(<RuleEditor templateKey="critical-to-oncall" />);
    expect(byLabel(host, "Name").value).toBe("Critical to on-call");
    expect(host.textContent).toContain("Before saving, choose who action 1 assigns to.");
    expect((byAria(host, "Condition 1: field")).value).toBe("input.issue.severity");
    expect((byAria(host, "Condition 1: value")).value).toBe("CRITICAL");
    await act(async () => button(host, "Test this rule").click());
    await flush();
    expect(host.textContent).toContain("Name a person by their @handle.");
    await setValue(byAria(host, "Action 1: person"), "priyan");
    await act(async () => button(host, "Add a condition").click());
    await setValue(byAria(host, "Condition 2: field"), "input.issue.tags");
    await setValue(byAria(host, "Condition 2: value"), "payments");
    await act(async () => button(host, "Test this rule").click());
    await flush();
    expect(host.querySelector(".ds-au-dry")?.textContent).toContain("would have matched 4 issues");
    const tested = calls.filter((c) => c.path === "/v2/rules/test").at(-1)!.body as { condition: string; actions: unknown[] };
    expect(tested.condition).toBe('input.issue.severity == "CRITICAL"\ninput.issue.tags[_] == "payments"');
    expect(tested.actions[0]).toEqual({ type: "assign", to: "priyan" });
    const results = await axe.run(host, AXE);
    expect(results.violations.map((v) => v.id)).toEqual([]);
    await act(async () => button(host, "Save rule").click());
    await flush();
    expect(calls.find((c) => c.method === "POST" && c.path === "/v2/rules")?.body).toMatchObject({ template: "critical-to-oncall" });
    expect(push).toHaveBeenCalledWith("/app/automation?saved=new-rule");
  });

  it("keeps a hand-written condition in the Rego view and shows OPA's error there", async () => {
    api((m, p) => {
      if (p === "/v2/rules/catalogue") return json(CAT);
      if (p === "/assets" || p === "/v2/people") return json([]);
      if (m === "GET" && p === `/v2/rules/r1`) return json({ id: "r1", name: "Hand-written", description: null, project_id: null, enabled: true, trigger: "issue.created",
        trigger_params: {}, condition: 'input.issue.severity in {"HIGH", "CRITICAL"}', actions: [{ type: "tag", tags: ["x"] }], confirm_over: 25, template: null });
      if (m === "PUT" && p === "/v2/rules/r1") return json({ detail: { field: "condition", message: "1 error occurred: line 1: rego_parse_error: unexpected eof token" } }, 422);
      return undefined;
    });
    const host = await mount(<RuleEditor ruleId="r1" />);
    const rego = byLabel(host, "Condition lines");
    expect(rego.value).toBe('input.issue.severity in {"HIGH", "CRITICAL"}');
    await act(async () => button(host, "Builder").click());
    expect(host.textContent).toContain("The builder cannot show this condition");
    await setValue(rego, "input.issue.severity ==");
    expect(host.querySelector(".ds-ed-module")?.textContent).toContain("  input.issue.severity ==");
    await act(async () => button(host, "Save changes").click());
    await flush();
    expect(host.querySelector(".ds-ed-pre")?.textContent).toContain("rego_parse_error");
    expect(rego.getAttribute("aria-invalid")).toBe("true");
    // A project trigger drops the issue-only actions it cannot run.
    await setValue(byLabel(host, "Trigger"), "project.quiet");
    expect(byLabel(host, "Days without a scan").value).toBe("14");
  });

  it("lets you type several tags and people", async () => {
    api((_m, p) => (p === "/v2/rules/catalogue" ? json(CAT) : p === "/assets" || p === "/v2/people" ? json([]) : undefined));
    const host = await mount(<RuleEditor />);
    const tags = byAria(host, "Action 1: tags");
    await setValue(tags, "payments ");
    expect(tags.value).toBe("payments ");
    await setValue(tags, "payments pci");
    expect(tags.value).toBe("payments pci");
  });
});

describe("inbox", () => {
  const inbox = (over: Partial<Inbox> = {}): Inbox => ({
    notifications: [
      { id: "n1", kind: "mention", title: "Priya N. mentioned you on “SQL injection”", body: "@arjunk can you look?", link: `/app/projects/${P}/issues/${I}`,
        issue_id: I, actor: "token:a", created_at: "2026-10-06T09:00:00Z", read: false, email: "pending" },
      { id: "n2", kind: "sla", title: "“SQL injection” breached its SLA", body: null, link: null, issue_id: I, actor: null,
        created_at: "2026-10-05T09:00:00Z", read: true, email: null },
    ], unread: 1, you: "token:b", person: true, names: {}, ...over,
  });

  it("lists, marks read, and is accessible", async () => {
    let state = inbox();
    const calls = api((m, p) => {
      if (p === "/v2/notifications" && m === "GET") return json(state);
      if (p === "/v2/notifications/read") { state = inbox({ unread: 0, notifications: state.notifications.map((n) => ({ ...n, read: true })) }); return json({ marked: 1, unread: 0 }); }
      return undefined;
    });
    const host = await mount(<InboxScreen />);
    expect(host.querySelector(".ds-au-verdict")?.textContent).toBe("1 unread.");
    expect(host.textContent).toContain("in your next daily digest");
    expect(host.querySelectorAll(".ds-in-unread")).toHaveLength(1);
    const results = await axe.run(host, AXE);
    expect(results.violations.map((v) => v.id)).toEqual([]);
    await act(async () => button(host, "Mark all read").click());
    await flush();
    expect(calls.find((c) => c.path === "/v2/notifications/read")?.body).toEqual({});
    expect(host.querySelector(".ds-au-verdict")?.textContent).toBe("You are up to date.");
    expect(inboxVerdict(inbox({ person: false }))).toContain("shared token");
  });
});

describe("notification settings", () => {
  const prefs = (over: Partial<NotificationPrefsView> = {}): NotificationPrefsView => ({
    owner: "token:b", email: null, digest_hour: 8, email_available: false, person: true,
    kinds: [{ key: "mention", label: "Someone mentions you in a note", modes: { in_app: "instant", email: "digest" } }],
    channels: { in_app: ["off", "instant"], email: ["off", "instant", "digest"] }, ...over,
  });
  it("saves yours and the team's, and says when there is no mail server", async () => {
    const calls = api((m, p, b) => {
      if (p === "/v2/notification-prefs" && m === "GET") return json(prefs());
      if (p === "/v2/notification-prefs" && m === "PUT") return json(prefs({ email: (b as { email: string }).email }));
      if (p === "/v2/notification-prefs/team" && m === "GET") return json(prefs({ owner: "team", person: undefined, channels: { team: ["off", "instant", "digest"] },
        kinds: [{ key: "scan", label: "A scan or import completes", modes: { team: "instant" } }] }));
      if (p === "/v2/notification-prefs/team" && m === "PUT") return json({ detail: "this token does not have the 'scans:write' scope" }, 403);
      return undefined;
    });
    const host = await mount(<NotificationSettings />);
    expect(host.textContent).toContain("No mail server is set up");
    await setValue(byAria(host, "Someone mentions you in a note: Email"), "instant");
    await setValue(byLabel(host, "Email address"), "arjun@acme.example");
    await act(async () => button(host, "Save yours").click());
    await flush();
    expect(calls.find((c) => c.method === "PUT" && c.path === "/v2/notification-prefs")?.body).toEqual({
      modes: { mention: { in_app: "instant", email: "instant" } }, digest_hour: 8, email: "arjun@acme.example" });
    await setValue(byAria(host, "A scan or import completes: Team channels"), "digest");
    await act(async () => button(host, "Save the team").click());
    await flush();
    expect(host.querySelector("[role=alert]")?.textContent).toContain("scans:write");
    const results = await axe.run(host, AXE);
    expect(results.violations.map((v) => v.id)).toEqual([]);
  });
});

describe("tickets on the issue page", () => {
  const view = (over: Partial<IssueTicket> = {}): IssueTicket => ({ ticket: null, group: null, configured: true, provider: "jira", status_source: "ticket", ...over });
  it("files the ticket, shows its status, and groups the issue", async () => {
    let state = view();
    const calls = api((m, p, b) => {
      if (p === `/v2/issues/${I}/ticket` && m === "GET") return json(state);
      if (p === `/v2/projects/${P}/groups`) return json(state.group ? [{ id: G, name: "jinja2 upgrade", project_id: P, count: 2, created_at: "" }] : []);
      if (p === `/v2/issues/${I}/ticket` && m === "POST") {
        state = view({ ticket: { provider: "jira", id: "PAY-1", url: "https://acme.atlassian.net/browse/PAY-1", status: "To Do", closed: false, assignee: "Mia Krystof", synced_at: null, group_id: null } });
        return json(state);
      }
      if (p === `/v2/issues/${I}/group`) {
        state = { ...state, group: { id: G, name: (b as { name: string }).name, count: 2 } };
        return json(state);
      }
      return undefined;
    });
    const host = await mount(<TicketPanel issueId={I} assetId={P} />);
    await act(async () => button(host, "File a ticket in Jira").click());
    await flush();
    expect(host.querySelector(".ds-tk-line")?.textContent).toBe("PAY-1 in Jira: To Do · Mia Krystof");
    expect(host.textContent).toContain("Status comes from the ticket");
    await setValue(byAria(host, "New group name"), "jinja2 upgrade");
    await act(async () => host.querySelector("form")!.requestSubmit());
    await flush();
    expect(calls.find((c) => c.path === `/v2/issues/${I}/group`)?.body).toEqual({ name: "jinja2 upgrade" });
    expect(host.textContent).toContain("One ticket tracks the group's 2 issues.");
    const results = await axe.run(host, AXE);
    expect(results.violations.map((v) => v.id)).toEqual([]);
  });

  it("points to the settings when the project files no tickets, and watches", async () => {
    let watching = false;
    api((m, p) => {
      if (p === `/v2/issues/${I}/ticket`) return json(view({ configured: false, provider: null }));
      if (p === `/v2/projects/${P}/groups`) return json([]);
      if (p === `/v2/issues/${I}/watchers`) return json({ watchers: [], watching: false, names: {} });
      if (p === `/v2/issues/${I}/watch`) { watching = m === "PUT"; return json({ watchers: watching ? [{ actor: "token:b", reason: "manual" }] : [], watching, names: { "token:b": "Arjun K." } }); }
      return undefined;
    });
    const host = await mount(<><WatchButton issueId={I} /><TicketPanel issueId={I} assetId={P} /></>);
    expect(host.textContent).toContain("This project files no tickets yet.");
    expect(host.querySelector(`a[href="/app/projects/${P}/tickets"]`)).not.toBeNull();
    await act(async () => button(host, "Watch").click());
    await flush();
    expect(host.textContent).toContain("Watching: Arjun K.");
  });
});

describe("ticket settings", () => {
  it("saves the target and the status map", async () => {
    const calls = api((m, p, b) => {
      if (p === `/v2/projects/${P}/tickets` && m === "GET") return json({ configured: false, provider: null, target: null, issue_type: null, status_source: "ticket",
        status_map: {}, effective_map: { done: "ready_for_retest" }, enabled: false, updated_by: null, updated_at: null, credentials: { jira: true, github: false } });
      if (p === `/v2/projects/${P}/tickets` && m === "PUT") return json({ configured: true, ...(b as object), effective_map: {}, updated_by: null, updated_at: null, credentials: { jira: true, github: false } });
      return undefined;
    });
    const host = await mount(<TicketSettingsScreen assetId={P} />);
    expect(host.textContent).toContain("“done” → Mark ready for retest");
    await setValue(byLabel(host, "Jira project key"), "PAY");
    await act(async () => button(host, "Add a status").click());
    await setValue(byAria(host, "Status 1"), "In Review");
    await act(async () => button(host, "Save").click());
    await flush();
    expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ provider: "jira", target: "PAY", status_source: "ticket",
      status_map: { "In Review": "ready_for_retest" }, enabled: true });
    expect(host.querySelector(".ds-au-verdict")?.textContent).toBe("Issues are filed in Jira project PAY.");
    const results = await axe.run(host, AXE);
    expect(results.violations.map((v) => v.id)).toEqual([]);
  });
});
