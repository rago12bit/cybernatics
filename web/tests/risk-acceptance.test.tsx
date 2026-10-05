// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RiskAcceptanceDetail } from "../components/RiskAcceptanceDetail";
import { RiskAcceptanceRequest } from "../components/RiskAcceptanceRequest";
import { RiskAcceptancesScreen, approvalsVerdict } from "../components/RiskAcceptancesScreen";
import type { RiskAcceptance } from "../lib/types";

vi.mock("next/navigation", () => ({ usePathname: () => "/app", useRouter: () => ({ push: vi.fn() }) }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const P = "11111111-1111-4111-8111-111111111111";
const POLICY = { max_days: 90, you: "token:alice", approvers: [{ actor: "token:bob", name: "Bob" }, { actor: "token:carol", name: "Carol" }], can_approve: true };

function ra(over: Partial<RiskAcceptance> = {}): RiskAcceptance {
  return {
    id: "ra1", project_id: P, project: "acme/web", decision: "accept", justification: "Retired on 30 November.",
    controls: "WAF rule 9412.", proof_links: ["https://wiki.example.com/waf"], proof_files: [], expires_at: "2026-11-30T23:59:00Z",
    days: 56, restart_sla: true, state: "requested", requested_by: "token:alice", requested_at: "2026-10-05T09:00:00Z",
    approver: null, decided_by: null, decided_at: null, decision_note: null, ended_at: null, ended_by: null,
    ended_reason: null, extends_id: null, legacy: false, issue_count: 2,
    issues: [{ id: "i1", title: "SQL injection", severity: "HIGH", path: "a.py", state: "open", triage_status: "open" }],
    trail: [{ at: "2026-10-05T09:00:00Z", actor: "token:alice", action: "requested" }], can_decide: false, ...over,
  };
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
type Call = { method: string; path: string; body?: unknown; form?: boolean };

function api(o: { one?: RiskAcceptance; list?: RiskAcceptance[]; create?: (b: unknown) => Response; policy?: typeof POLICY } = {}) {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const path = new URL(String(url)).pathname;
    const method = init?.method ?? "GET";
    const form = init?.body instanceof FormData;
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ method, path, body, form });
    if (path === "/v2/risk-acceptance-policy") return json(o.policy ?? POLICY);
    if (path.endsWith("/risk-acceptances") && method === "POST") return o.create ? o.create(body) : json(ra(), 201);
    if (path.endsWith("/attachments")) return json({ id: "f1", file_name: "x.png" }, 201);
    if (path === "/v2/risk-acceptances") return json(o.list ?? []);
    if (path.endsWith("/approve")) return json(ra({ state: "approved", decided_by: "token:bob" }));
    if (path.endsWith("/reject")) return json(ra({ state: "rejected", decided_by: "token:bob", decision_note: body?.note }));
    if (path.startsWith("/v2/risk-acceptances/")) return json(o.one ?? ra());
    return json({}, 404);
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
const button = (host: HTMLElement, text: string) =>
  Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.trim().startsWith(text)) as HTMLButtonElement | undefined;
const byLabel = (host: HTMLElement, label: string) => {
  const l = Array.from(host.querySelectorAll("label")).find((x) => x.textContent?.trim() === label)!;
  return host.querySelector(`#${CSS.escape(l.htmlFor)}`) as HTMLInputElement;
};
async function setValue(el: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement, value: string) {
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(el, value);
  await act(async () => el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? "change" : "input", { bubbles: true })));
}

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("the request form (§55.3)", () => {
  it("sends the decision, why, controls, proof, expiry, approver and SLA restart, then the files", async () => {
    const calls = api();
    const done = vi.fn();
    const host = await mount(<RiskAcceptanceRequest assetId={P} issueIds={["i1", "i2"]} onDone={done} onCancel={vi.fn()} />);
    expect(host.textContent).toContain("Policy maximum: 90 days");
    const approver = byLabel(host, "Approver") as unknown as HTMLSelectElement;
    expect(Array.from(approver.options).map((o) => o.textContent)).toEqual(["Someone other than you", "Bob", "Carol"]);
    await act(async () => (host.querySelector('input[value="mitigate"]') as HTMLInputElement).click());
    await setValue(byLabel(host, "Why") as unknown as HTMLTextAreaElement, "Retired on 30 November.");
    await setValue(byLabel(host, "Controls") as unknown as HTMLTextAreaElement, "WAF rule 9412.");
    await setValue(byLabel(host, "Proof (links and files)"), "https://wiki.example.com/waf");
    await act(async () => button(host, "Add link")!.click());
    const file = new File([new Uint8Array([137, 80, 78, 71])], "waf.png", { type: "image/png" });
    const fileInput = host.querySelector('input[type="file"]') as HTMLInputElement;
    Object.defineProperty(fileInput, "files", { value: [file] });
    await act(async () => fileInput.dispatchEvent(new Event("change", { bubbles: true })));
    await setValue(byLabel(host, "Expires"), "2026-11-30");
    await setValue(approver, "token:bob");
    expect(host.textContent).toContain("Bob gets a notification. The issues stay open until someone else approves.");
    await act(async () => button(host, "Send request")!.click());
    await flush();
    const post = calls.find((c) => c.method === "POST" && c.path.endsWith("/risk-acceptances"))!;
    expect(post.path).toBe(`/v2/projects/${P}/risk-acceptances`);
    expect(post.body).toMatchObject({ issue_ids: ["i1", "i2"], decision: "mitigate", justification: "Retired on 30 November.",
      controls: "WAF rule 9412.", proof_links: ["https://wiki.example.com/waf"], restart_sla: true, approver: "token:bob" });
    expect(String((post.body as { expires_at: string }).expires_at)).toMatch(/^2026-11-30T|^2026-12-01T/);
    expect(calls.some((c) => c.path === "/v2/risk-acceptances/ra1/attachments" && c.form)).toBe(true);
    expect(done).toHaveBeenCalled();
  });

  it("puts the server's field error on the field", async () => {
    api({ create: () => json({ detail: { field: "controls", message: "Compensating controls is required" } }, 422) });
    const host = await mount(<RiskAcceptanceRequest assetId={P} issueIds={["i1"]} onDone={vi.fn()} onCancel={vi.fn()} />);
    await setValue(byLabel(host, "Expires"), "2026-11-30");
    await act(async () => button(host, "Send request")!.click());
    await flush();
    const controls = byLabel(host, "Controls");
    expect(controls.getAttribute("aria-invalid")).toBe("true");
    expect(document.getElementById(controls.getAttribute("aria-describedby")!)!.textContent).toBe("Compensating controls is required");
  });

  it("has no accessibility violations", async () => {
    api();
    const host = await mount(<RiskAcceptanceRequest assetId={P} issueIds={["i1"]} onDone={vi.fn()} onCancel={vi.fn()} />);
    const r = await axe.run(host, { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } });
    expect(r.violations.map((v) => v.id)).toEqual([]);
  });
});

describe("approvals", () => {
  it("says what is waiting, and for whom", () => {
    expect(approvalsVerdict([])).toBe("Nothing is waiting for approval.");
    expect(approvalsVerdict([ra()])).toBe("1 request waiting for someone else's decision.");
    expect(approvalsVerdict([ra({ can_decide: true }), ra({ id: "b", can_decide: true })])).toBe("2 requests waiting for your decision.");
  });

  it("lists waiting, in force and ended", async () => {
    api({ list: [ra({ can_decide: true }), ra({ id: "b", state: "approved" }), ra({ id: "c", state: "expired", legacy: true })] });
    const host = await mount(<RiskAcceptancesScreen />);
    const sections = Array.from(host.querySelectorAll("section")).map((s) => [s.querySelector("h2")!.textContent, s.querySelectorAll("li").length]);
    expect(sections).toEqual([["Waiting for approval", 1], ["In force", 1], ["Ended", 1]]);
    expect(host.textContent).toContain("accepted alone, before approvals");
  });

  it("shows approve and reject only when the server says you may decide; rejecting needs a note", async () => {
    api({ one: ra({ can_decide: false }) });
    let host = await mount(<RiskAcceptanceDetail id="ra1" />);
    expect(button(host, "Approve")).toBeUndefined();
    expect(host.textContent).toContain("You asked for this, so someone else has to decide.");
    expect(button(host, "Withdraw request")).toBeDefined();
    await act(async () => root!.unmount());

    const calls = api({ one: ra({ can_decide: true, requested_by: "token:carol" }) });
    host = await mount(<RiskAcceptanceDetail id="ra1" />);
    expect(button(host, "Reject")!.disabled).toBe(true);
    await setValue(host.querySelector("textarea") as HTMLTextAreaElement, "Not retired yet.");
    await act(async () => button(host, "Reject")!.click());
    await flush();
    expect(calls.find((c) => c.path.endsWith("/reject"))!.body).toEqual({ note: "Not retired yet." });
    expect(host.textContent).toContain("Rejected");
  });

  it("offers expire now and extend for an approved one; the shared token is told why it cannot decide", async () => {
    api({ one: ra({ state: "approved", decided_by: "token:bob" }) });
    let host = await mount(<RiskAcceptanceDetail id="ra1" />);
    expect(button(host, "Expire now")).toBeDefined();
    expect(host.textContent).toContain("An extension is a new request; someone other than you approves it.");
    await act(async () => root!.unmount());
    api({ one: ra({ requested_by: "token:zed" }), policy: { ...POLICY, you: "shared-token", can_approve: false } });
    host = await mount(<RiskAcceptanceDetail id="ra1" />);
    expect(host.textContent).toContain("Deciding needs a personal API token");
    const r = await axe.run(host, { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } });
    expect(r.violations.map((v) => v.id)).toEqual([]);
  });
});
