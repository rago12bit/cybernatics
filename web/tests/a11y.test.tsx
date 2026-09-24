// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DemoReport } from "../components/DemoReport";
import { FindingDetail } from "../components/FindingDetail";
import { Landing } from "../components/site/Landing";
import { SiteHeader } from "../components/site/SiteHeader";
import { TokenGate } from "../components/TokenGate";
import type { Finding } from "../lib/types";
import demo from "../lib/demo-data.json";

let path = "/";
vi.mock("next/navigation", () => ({ usePathname: () => path, useRouter: () => ({ push: () => undefined }) }));
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
afterEach(() => { document.body.innerHTML = ""; sessionStorage.clear(); path = "/"; });

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
    expect(host.querySelector("a[href='/demo']")).not.toBeNull(); // and a way forward without a token
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
    path = "/demo";
    const a = await mount(<SiteHeader />);
    expect(a.host.querySelector("nav a[aria-current='page']")?.textContent).toBe("Demo");
    expect(a.host.textContent).not.toContain("Sign out");
    await act(async () => a.root.unmount());
    sessionStorage.setItem("bulwark.token", "x".repeat(20));
    path = "/app";
    const b = await mount(<SiteHeader />);
    expect(b.host.textContent).toContain("Sign out");
  });
});
