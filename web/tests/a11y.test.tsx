// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DemoReport } from "../components/DemoReport";
import { FindingDetail } from "../components/FindingDetail";
import { RecentScans } from "../components/RecentScans";
import { SubmitForm } from "../components/SubmitForm";
import { Landing } from "../components/site/Landing";
import { SiteHeader } from "../components/site/SiteHeader";
import { TokenGate } from "../components/TokenGate";
import SelfHost from "../app/self-host/page";
import type { Finding } from "../lib/types";
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
    expect(host.querySelector("a[href='/']")).not.toBeNull(); // and a way forward without a token
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
    expect(a.host.querySelector("nav a[aria-current='page']")?.textContent).toBe("Sample scan");
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
