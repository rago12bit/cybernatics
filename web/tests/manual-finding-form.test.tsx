// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ManualFindingForm, parseVector } from "../components/ManualFindingForm";
import { ManualFindingPanel } from "../components/ManualFindingPanel";
import type { ManualFindingView } from "../lib/types";

vi.mock("next/navigation", () => ({ usePathname: () => "/app", useRouter: () => ({ push: vi.fn() }) }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const ASSET = "11111111-1111-4111-8111-111111111111";
const ISSUE = "22222222-2222-4222-8222-222222222222";
const MANUAL = "33333333-3333-4333-8333-333333333333";
const IDOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N";
const ROUTES = [
  { method: "GET", route: "/v2/orders/{id}", path: "app/orders.py", line: 40, symbol: "get_order", framework: "fastapi" },
  { method: "POST", route: "/v2/orders", path: "app/orders.py", line: 80, symbol: "create_order", framework: "fastapi" },
];

function manual(over: Partial<ManualFindingView> = {}): ManualFindingView {
  return {
    id: MANUAL, issue_id: ISSUE, import_id: "i1", asset_id: ASSET, test_id: "t1",
    title: "IDOR on orders", cwe: "CWE-639", cwe_name: "Authorization Bypass Through User-Controlled Key",
    severity: "HIGH", cvss_vector: IDOR, cvss_score: 7.1, location_kind: "route", method: "GET",
    route: "/v2/orders/{id}", host: null, path: "app/orders.py", line: 40,
    steps: "1. Sign in as A\n2. Read B's order", impact: "Any order is readable.", recommendation: "Check ownership.",
    references: ["https://cwe.mitre.org/data/definitions/639.html"], related_issue_id: null, related_source: null,
    created_by: "token:abc", created_at: "2026-10-05T00:00:00Z", attachments: [], ...over,
  };
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

type Call = { method: string; path: string; body?: unknown; form?: FormData };

function api(o: { record?: (body: Record<string, unknown>) => Response; routes?: unknown[]; manual?: ManualFindingView[] } = {}) {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    const form = init?.body instanceof FormData ? init.body : undefined;
    calls.push({ method, path: u.pathname, body, form });
    if (u.pathname === `/v2/projects/${ASSET}/routes`) return json({ scan_id: "s1", routes: o.routes ?? ROUTES });
    if (u.pathname === "/v2/cwe") return json([{ id: "CWE-639", name: "Authorization Bypass Through User-Controlled Key" }]);
    if (u.pathname === "/v2/cvss/v4") {
      return body.vector === IDOR
        ? json({ vector: IDOR, score: 7.1, rating: "High", severity: "HIGH" })
        : json({ vector: body.vector, score: 5.0, rating: "Medium", severity: "MEDIUM" });
    }
    if (u.pathname === `/v2/projects/${ASSET}/manual-findings` && method === "POST") {
      return o.record ? o.record(body) : json({ manual: manual(), issue_id: ISSUE, import_id: "i1", created: true }, 201);
    }
    if (u.pathname === `/v2/projects/${ASSET}/manual-findings`) return json(o.manual ?? []);
    if (u.pathname === `/v2/manual-findings/${MANUAL}/attachments`) {
      const f = form!.get("file") as File;
      return json({ id: "a1", file_name: f.name, declared_type: f.type, sniffed_type: "image/png",
        active_content: false, size_bytes: f.size, sha256: "x", encrypted: true, created_at: "2026-10-05T00:00:00Z" }, 201);
    }
    if (u.pathname === "/v2/attachments/a1/link") return json({ url: "/v2/attachments/a1/download?token=t", expires_at: "x" });
    return json({}, 404);
  }));
  return calls;
}

let root: Root | null = null;
const flush = (ms = 40) => act(async () => { await new Promise((r) => setTimeout(r, ms)); });

async function mount(node: React.ReactElement) {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(node));
  await flush(260);
  return host;
}

const field = (host: HTMLElement, label: string) => {
  const l = Array.from(host.querySelectorAll("label")).find((x) => x.textContent?.trim() === label)!;
  return host.querySelector(`#${CSS.escape(l.htmlFor)}`) as HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
};

async function setValue(el: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement, value: string) {
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype
    : el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(el, value);
  await act(async () => el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? "change" : "input", { bubbles: true })));
}

async function click(el: Element) {
  await act(async () => (el as HTMLElement).click());
  await flush();
}

const button = (host: HTMLElement, text: string) =>
  Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.trim() === text) as HTMLButtonElement;

async function useIdorVector(host: HTMLElement) {
  await setValue(field(host, "Or paste a vector") as HTMLInputElement, IDOR);
  await click(button(host, "Use vector"));
  await flush(60);
}

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("ManualFindingForm", () => {
  it("parses a pasted vector into base metrics and keeps the rest", () => {
    expect(parseVector(`${IDOR}/E:U`)).toEqual({
      metrics: { AV: "N", AC: "L", AT: "N", PR: "L", UI: "N", VC: "H", VI: "N", VA: "N", SC: "N", SI: "N", SA: "N" },
      extra: ["E:U"],
    });
  });

  it("scores the vector on the server and shows FIRST's rating with the vector", async () => {
    const calls = api();
    const host = await mount(<ManualFindingForm assetId={ASSET} />);
    await useIdorVector(host);
    expect(calls.some((c) => c.path === "/v2/cvss/v4" && c.body && (c.body as { vector: string }).vector === IDOR)).toBe(true);
    expect(host.querySelector(".ds-mf-score")!.textContent).toContain("7.1 High");
    expect(host.querySelector(".ds-mf-score code")!.textContent).toBe(IDOR);
    const checked = host.querySelector('input[type=radio][value="L"]:checked') as HTMLInputElement;
    expect(checked).not.toBeNull();
  });

  it("offers the latest scan's routes, with their handlers", async () => {
    api();
    const host = await mount(<ManualFindingForm assetId={ASSET} />);
    const options = Array.from((field(host, "Route") as HTMLSelectElement).options).map((o) => o.textContent);
    expect(options).toContain("GET    /v2/orders/{id} — app/orders.py:40");
    expect(options.at(-1)).toBe("Another route…");
  });

  it("on submit with problems, lists them at the top and puts each next to its field", async () => {
    const calls = api();
    const host = await mount(<ManualFindingForm assetId={ASSET} />);
    await click(button(host, "Record finding"));
    const summary = host.querySelector(".ds-mf-summary")!;
    expect(summary.getAttribute("role")).toBe("alert");
    expect(summary.textContent).toContain("3 things need fixing");
    const title = field(host, "Title");
    expect(title.getAttribute("aria-invalid")).toBe("true");
    const err = document.getElementById(title.getAttribute("aria-describedby")!)!;
    expect(err.textContent).toBe("Give the finding a title.");
    expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/manual-findings"))).toBe(false);
  });

  it("records the finding with the picked route, then uploads the evidence", async () => {
    const calls = api();
    const host = await mount(<ManualFindingForm assetId={ASSET} />);
    await setValue(field(host, "Title") as HTMLInputElement, "IDOR on orders");
    await setValue(field(host, "Weakness (CWE)") as HTMLInputElement, "CWE-639");
    await useIdorVector(host);
    await setValue(field(host, "Route") as HTMLSelectElement, "GET|/v2/orders/{id}|app/orders.py|40");
    await setValue(field(host, "Steps to reproduce") as HTMLTextAreaElement, "1. Sign in as A");
    await setValue(field(host, "References") as HTMLTextAreaElement, "https://cwe.mitre.org/data/definitions/639.html\n");
    const ev = field(host, "Evidence") as HTMLInputElement;
    const file = new File([new Uint8Array([137, 80, 78, 71])], "shot.png", { type: "image/png" });
    Object.defineProperty(ev, "files", { value: [file], configurable: true });
    await act(async () => ev.dispatchEvent(new Event("change", { bubbles: true })));
    await click(button(host, "Record finding"));
    await flush(60);
    const post = calls.find((c) => c.method === "POST" && c.path === `/v2/projects/${ASSET}/manual-findings`)!;
    expect(post.body).toMatchObject({
      title: "IDOR on orders", cwe: "CWE-639", cvss_vector: IDOR, severity: null, location_kind: "route",
      method: "GET", route: "/v2/orders/{id}", steps: "1. Sign in as A",
      references: ["https://cwe.mitre.org/data/definitions/639.html"],
    });
    expect(calls.some((c) => c.path === `/v2/manual-findings/${MANUAL}/attachments`)).toBe(true);
    expect(host.querySelector(".ds-mf-done")!.textContent).toContain("Recorded: IDOR on orders — 7.1 High (CVSS 4.0)");
    expect(host.textContent).toContain("1 evidence file attached, encrypted at rest.");
    const open = Array.from(host.querySelectorAll("a")).find((a) => a.textContent === "Open the issue")!;
    expect(open.getAttribute("href")).toBe(`/app/projects/${ASSET}/issues/${ISSUE}`);
  });

  it("says when automation already found it", async () => {
    api({ record: () => json({ manual: manual({ related_issue_id: "44444444-4444-4444-8444-444444444444", related_source: "opengrep" }),
      issue_id: ISSUE, import_id: "i1", created: true }, 201) });
    const host = await mount(<ManualFindingForm assetId={ASSET} />);
    await setValue(field(host, "Title") as HTMLInputElement, "IDOR");
    await useIdorVector(host);
    await setValue(field(host, "Route") as HTMLSelectElement, "GET|/v2/orders/{id}|app/orders.py|40");
    await click(button(host, "Record finding"));
    expect(host.textContent).toContain("Also found by opengrep");
  });

  it("shows a server field error next to its field", async () => {
    api({ record: () => json({ detail: { field: "route", message: "Pick a route, or type one that starts with '/'." } }, 422) });
    const host = await mount(<ManualFindingForm assetId={ASSET} />);
    await setValue(field(host, "Title") as HTMLInputElement, "IDOR");
    await useIdorVector(host);
    await setValue(field(host, "Route") as HTMLSelectElement, "GET|/v2/orders/{id}|app/orders.py|40");
    await click(button(host, "Record finding"));
    expect(field(host, "Route").getAttribute("aria-invalid")).toBe("true");
    expect(host.querySelector(".ds-mf-summary")!.textContent).toContain("Pick a route");
  });

  it("lets a person type a route when the project has none recorded, and set severity without CVSS", async () => {
    const calls = api({ routes: [] });
    const host = await mount(<ManualFindingForm assetId={ASSET} />);
    await setValue(field(host, "Title") as HTMLInputElement, "Verbose errors");
    await setValue(field(host, "Route path") as HTMLInputElement, "/debug");
    await click(host.querySelector(".ds-mf-nocvss input")!);
    await setValue(field(host, "Severity") as HTMLSelectElement, "LOW");
    await click(button(host, "Record finding"));
    const post = calls.find((c) => c.method === "POST" && c.path.endsWith("/manual-findings"))!;
    expect(post.body).toMatchObject({ route: "/debug", method: "GET", cvss_vector: null, severity: "LOW" });
  });

  it("has no accessibility violations, empty and with errors shown", async () => {
    api();
    const host = await mount(<ManualFindingForm assetId={ASSET} />);
    const rules = { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } };
    expect((await axe.run(host, rules)).violations.map((v) => v.id)).toEqual([]);
    await click(button(host, "Record finding"));
    expect((await axe.run(host, rules)).violations.map((v) => v.id)).toEqual([]);
  });
});

describe("ManualFindingPanel", () => {
  it("renders nothing for an issue nobody recorded", async () => {
    api({ manual: [] });
    const host = await mount(<ManualFindingPanel assetId={ASSET} issueId={ISSUE} />);
    expect(host.innerHTML).toBe("");
  });

  it("shows the vector, the steps as text, and evidence only as a download", async () => {
    api({ manual: [manual({
      steps: "<img src=x onerror=alert(1)>",
      attachments: [{ id: "a1", file_name: "page.html", declared_type: "image/png", sniffed_type: "text/html",
        active_content: true, size_bytes: 2048, sha256: "x", encrypted: true, created_at: "2026-10-05T00:00:00Z" }],
    })] });
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign });
    const host = await mount(<ManualFindingPanel assetId={ASSET} issueId={ISSUE} />);
    expect(host.textContent).toContain(IDOR);
    expect(host.querySelector("img")).toBeNull(); // the steps are text, never markup
    expect(host.textContent).toContain("<img src=x onerror=alert(1)>");
    expect(host.querySelector("iframe, object, embed")).toBeNull(); // evidence is never shown
    expect(host.textContent).toContain("can contain script: opens only as a download");
    await click(button(host, "Download page.html"));
    expect(assign).toHaveBeenCalledWith(expect.stringMatching(/\/v2\/attachments\/a1\/download\?token=t$/));
  });
});
