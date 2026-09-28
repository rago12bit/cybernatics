// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ReportDownloads } from "../components/ReportDownloads";
import { setToken } from "../lib/api";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const ID = "11111111-2222-3333-4444-555555555555";

async function mount() {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  await act(async () => createRoot(host).render(<ReportDownloads scanId={ID} />));
  return host;
}
// Poll instead of a fixed sleep: a hardcoded 20ms delay assumed the mocked fetch + blob parsing
// (a real, multi-microtask async chain, not something `act` flushes synchronously) would always
// settle in time, which a busier or more parallelized CI runner can't guarantee. Wait for the
// actual completion signal instead -- the mocked fetch was called (the handler started) and every
// button is enabled again (its `finally` ran, whichever way the download settled).
async function waitFor(cond: () => boolean, timeoutMs = 2000, stepMs = 5) {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor: timed out");
    await new Promise((r) => setTimeout(r, stepMs));
  }
}
const click = async (host: HTMLElement, label: string) =>
  act(async () => {
    [...host.querySelectorAll("button")].find((b) => b.textContent === label)!.click();
    await waitFor(
      () =>
        (globalThis.fetch as unknown as { mock: { calls: unknown[] } }).mock.calls.length > 0 &&
        [...host.querySelectorAll("button")].every((b) => !b.disabled),
    );
  });
afterEach(() => { vi.unstubAllGlobals(); sessionStorage.clear(); document.body.innerHTML = ""; });

describe("report downloads", () => {
  it("offers PDF, HTML and SARIF, and requests the right format with the token in a header only", async () => {
    setToken("t".repeat(24));
    const fetchMock = vi.fn(async () => new Response(new Blob(["x"]), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    URL.createObjectURL = vi.fn(() => "blob:x");
    URL.revokeObjectURL = vi.fn();
    const host = await mount();
    expect([...host.querySelectorAll("button")].map((b) => b.textContent)).toEqual(["PDF", "HTML", "SARIF"]);
    await click(host, "SARIF");
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toContain(`/scans/${ID}/export?format=sarif`);
    expect(url).not.toContain("t".repeat(24)); // the token never goes in the URL
    expect((init.headers as Record<string, string>).Authorization).toBe(`Bearer ${"t".repeat(24)}`);
    expect(URL.createObjectURL).toHaveBeenCalled();
  });

  it("shows the server's message when the download fails, and re-enables the buttons", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ detail: "the scan has not finished" }), { status: 409 })));
    const host = await mount();
    await click(host, "PDF");
    expect(host.querySelector("[role=alert]")?.textContent).toBe("the scan has not finished");
    expect([...host.querySelectorAll("button")].every((b) => !b.disabled)).toBe(true);
  });

  it("reports an unreachable API in plain words", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("network"); }));
    const host = await mount();
    await click(host, "HTML");
    expect(host.querySelector("[role=alert]")?.textContent).toContain("Cannot reach the Bulwark API");
  });
});
