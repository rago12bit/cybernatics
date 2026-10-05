// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ConnectorsScreen, verdict } from "../components/ConnectorsScreen";
import type { ConnectorView } from "../lib/types";

vi.mock("next/navigation", () => ({ usePathname: () => "/app", useRouter: () => ({ push: vi.fn() }) }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const P = "11111111-1111-4111-8111-111111111111";

function conn(over: Partial<ConnectorView> = {}): ConnectorView {
  return {
    id: "c1", project_id: P, project: "acme/web", kind: "github_code_scanning", kind_label: "GitHub code scanning",
    direction: "pull", name: "Web code scanning", config: { repo: "acme/web" }, enabled: true, interval_minutes: 360,
    close_on_empty: false, credential_store: "none", test_id: "t1", status: "ok", warning: null,
    last_run_at: new Date().toISOString(), last_success_at: new Date(Date.now() - 2 * 3600e3).toISOString(),
    next_run_at: null, last_items: 12, max_items_seen: 12, consecutive_failures: 0, last_error: null, runs: [], ...over,
  };
}

const KINDS = [
  { name: "gitlab", label: "GitLab vulnerability report", direction: "pull", needs_credential: true,
    fields: ["base_url", "project"], permissions: "A token with the read_api scope." },
  { name: "defectdojo_export", label: "DefectDojo (export to)", direction: "push", needs_credential: true,
    fields: ["base_url"], permissions: "An API v2 key." },
];

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

type Call = { method: string; path: string; body?: unknown };

function api(list: ConnectorView[], o: { create?: (b: unknown) => Response } = {}) {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const path = new URL(String(url)).pathname;
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ method, path, body });
    if (path === "/v2/connectors" && method === "GET") return json(list);
    if (path === "/v2/connectors" && method === "POST") return o.create ? o.create(body) : json(conn({ id: "c9" }), 201);
    if (path === "/v2/connector-kinds") return json(KINDS);
    if (path === "/assets") return json([{ id: P, label: "acme/web" }]);
    if (path.endsWith("/run")) return json(list[0], 202);
    if (path.startsWith("/v2/connectors/") && method === "PATCH") return json({ ...list[0], enabled: false });
    if (path.startsWith("/v2/connectors/")) return json({ ...list[0], runs: [
      { id: "r1", started_at: new Date().toISOString(), finished_at: null, outcome: "ok", items: 12, requests: 1,
        import_id: "i1", counts: { new: 2, reopened: 0, closed: 1, unchanged: 10 }, warnings: [], error: null },
      { id: "r0", started_at: new Date().toISOString(), finished_at: null, outcome: "failed", items: 0, requests: 1,
        import_id: null, counts: {}, warnings: [], error: "GitHub code scanning: the credential was refused (HTTP 403)" },
    ] });
    return json({}, 404);
  }));
  return calls;
}

let root: Root | null = null;
const flush = (ms = 40) => act(async () => { await new Promise((r) => setTimeout(r, ms)); });
async function mount() {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<ConnectorsScreen />));
  await flush();
  return host;
}
const button = (host: HTMLElement, text: string) =>
  Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.trim().startsWith(text)) as HTMLButtonElement;
async function setValue(el: HTMLInputElement | HTMLSelectElement, value: string) {
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(el, value);
  await act(async () => el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? "change" : "input", { bubbles: true })));
}
const field = (host: HTMLElement, label: string) => {
  const l = Array.from(host.querySelectorAll("label")).find((x) => x.textContent?.trim() === label)!;
  return host.querySelector(`#${CSS.escape(l.htmlFor)}`) as HTMLInputElement | HTMLSelectElement;
};

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("ConnectorsScreen", () => {
  it("opens with a verdict that names what needs attention", () => {
    expect(verdict([])).toBe("No connectors yet.");
    expect(verdict([conn(), conn({ id: "c2" })])).toBe("All 2 connectors are healthy.");
    expect(verdict([conn(), conn({ id: "c2", name: "Dojo", status: "failing" }), conn({ id: "c3", name: "GitLab", status: "empty" })]))
      .toBe("2 of 3 connectors need attention: Dojo is failing; GitLab connected but fetched nothing.");
  });

  it("shows each connector's health as a word, last success, what it fetched, and the quiet failure", async () => {
    api([conn(), conn({ id: "c2", name: "GitLab", status: "empty", last_items: 0,
      warning: "Connected, but fetched nothing. If you expected findings, check the project or product and what the credential is allowed to see." })]);
    const host = await mount();
    const rows = Array.from(host.querySelectorAll(".ds-conn-table tbody > tr:first-child"));
    expect(rows.map((r) => r.querySelector(".ds-conn-status")!.textContent!.trim())).toEqual(["● Healthy", "◐ Fetched nothing"]);
    expect(rows[0]!.textContent).toContain("2 hours ago");
    expect(rows[0]!.textContent).toContain("12");
    expect(host.querySelector(".ds-conn-warning")!.textContent).toContain("Connected, but fetched nothing");
    expect(host.querySelector(".ds-conn-verdict")!.textContent).toContain("1 of 2 connectors needs attention");
  });

  it("runs a connector now, and shows its run history with what changed", async () => {
    const calls = api([conn()]);
    const host = await mount();
    await act(async () => button(host, "Run now").click());
    await flush();
    expect(calls.some((c) => c.method === "POST" && c.path === "/v2/connectors/c1/run")).toBe(true);
    await act(async () => button(host, "Runs").click());
    await flush();
    const runs = host.querySelector(".ds-conn-runs")!.textContent!;
    expect(runs).toContain("2 new, 0 reopened, 1 closed");
    expect(runs).toContain("the credential was refused (HTTP 403)");
  });

  it("adds a connector with the access it needs spelled out, and never echoes the credential", async () => {
    const calls = api([]);
    const host = await mount();
    await act(async () => button(host, "Add a connector").click());
    await flush();
    await setValue(field(host, "Project"), P);
    await setValue(field(host, "Connect to"), "gitlab");
    expect(host.textContent).toContain("Access it needs: A token with the read_api scope.");
    await setValue(field(host, "Base URL") as HTMLInputElement, "https://gitlab.com");
    await setValue(field(host, "Project path (group/name)") as HTMLInputElement, "acme/web");
    const cred = field(host, "Credential") as HTMLInputElement;
    expect(cred.type).toBe("password");
    await setValue(cred, "glpat-secret");
    await act(async () => button(host, "Add connector").click());
    await flush();
    const post = calls.find((c) => c.method === "POST" && c.path === "/v2/connectors")!;
    expect(post.body).toMatchObject({ project_id: P, kind: "gitlab", credential: "glpat-secret", close_on_empty: false,
      config: { base_url: "https://gitlab.com", project: "acme/web" } });
  });

  it("exports to a DefectDojo product created if needed, with the product type it needs", async () => {
    const calls = api([]);
    const host = await mount();
    await act(async () => button(host, "Add a connector").click());
    await flush();
    await setValue(field(host, "Project"), P);
    await setValue(field(host, "Connect to"), "defectdojo_export");
    const create = Array.from(host.querySelectorAll("label")).find((l) => l.textContent?.includes("created if needed"))!;
    await act(async () => (create.querySelector("input") as HTMLInputElement).click());
    await setValue(field(host, "Base URL") as HTMLInputElement, "https://dojo.example.com");
    await setValue(field(host, "DefectDojo product") as HTMLInputElement, "acme-web");
    await setValue(field(host, "DefectDojo engagement") as HTMLInputElement, "From Bulwark");
    expect((field(host, "Product type, for a new product") as HTMLInputElement).placeholder).toBe("Bulwark");
    await setValue(field(host, "Product type, for a new product") as HTMLInputElement, "Web apps");
    await setValue(field(host, "Credential") as HTMLInputElement, "dd-key");
    await act(async () => button(host, "Add connector").click());
    await flush();
    const post = calls.find((c) => c.method === "POST" && c.path === "/v2/connectors")!;
    expect(post.body).toMatchObject({ kind: "defectdojo_export", config: { base_url: "https://dojo.example.com",
      product_name: "acme-web", engagement_name: "From Bulwark", product_type_name: "Web apps" } });
  });

  it("shows a server field error next to the field", async () => {
    api([], { create: () => json({ detail: { field: "base_url", message: "only https:// URLs are allowed" } }, 422) });
    const host = await mount();
    await act(async () => button(host, "Add a connector").click());
    await flush();
    await setValue(field(host, "Project"), P);
    await setValue(field(host, "Connect to"), "gitlab");
    await setValue(field(host, "Base URL") as HTMLInputElement, "http://gitlab.internal");
    await act(async () => button(host, "Add connector").click());
    await flush();
    const input = field(host, "Base URL");
    expect(input.getAttribute("aria-invalid")).toBe("true");
    expect(document.getElementById(input.getAttribute("aria-describedby")!)!.textContent).toBe("only https:// URLs are allowed");
  });

  it("has no accessibility violations, with a warning and the add form open", async () => {
    api([conn({ status: "failing", warning: "Failed 3 times in a row: HTTP 502" })]);
    const host = await mount();
    await act(async () => button(host, "Add a connector").click());
    await flush();
    const r = await axe.run(host, { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } });
    expect(r.violations.map((v) => v.id)).toEqual([]);
  });
});
