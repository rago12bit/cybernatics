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
// settle in time, which a busier or more parallelized CI runner can't guarantee.
//
// Three things went wrong here before this version, each worth recording so a future attempt
// doesn't repeat any of them:
//  1. Waiting for "fetch was called AND every button is enabled" as one condition: fetchReport()
//     is called *synchronously*, before download()'s first `await` yields, so there's a real
//     window right after the click where fetch has already been called but React hasn't
//     re-rendered with the disabled state yet -- both halves of that one condition can be
//     trivially true before the click has done anything at all.
//  2. Waiting in two explicit phases (disabled, then enabled again), to close that gap: this
//     assumed the disabled state is always independently observable, but when the mock
//     resolves/rejects with no real delay, React can batch the whole disabled -> enabled cycle
//     into a single commit -- the intermediate disabled state is never externally observable,
//     so phase one just times out.
//  3. Polling *inside* the same `act(async () => {...})` call as the click: `act` defers
//     flushing state updates until its own callback settles, so a poll loop nested inside it
//     never observes anything change -- confirmed by dumping the DOM at the timeout and finding
//     the button stuck mid-flight ("Preparing…") for the full 2s, with no fetch response ever
//     appearing to land. The click gets its own short `act()`; the poll runs after it, outside
//     any `act()` call, so it can actually see each update as `act`'s automatic batching lands it.
// The wait condition itself is the actual thing each caller is about to assert on next -- there's
// no ambiguous window for "the alert text appeared" or "createObjectURL was called" to be
// trivially true before the click did anything, unlike (1) and (2) above.
// 5s, not 2s: a correctly-written wait can still lose to CI scheduler jitter under the real
// CPU oversubscription described in vitest.config.ts (17 worker processes on a 2-CPU runner).
async function waitFor(cond: () => boolean, timeoutMs = 5000, stepMs = 5) {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor: timed out");
    await new Promise((r) => setTimeout(r, stepMs));
  }
}
const click = async (host: HTMLElement, label: string, until: () => boolean) => {
  await act(async () => {
    [...host.querySelectorAll("button")].find((b) => b.textContent === label)!.click();
  });
  await waitFor(until);
};
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
    await click(host, "SARIF", () => (URL.createObjectURL as ReturnType<typeof vi.fn>).mock.calls.length > 0);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toContain(`/scans/${ID}/export?format=sarif`);
    expect(url).not.toContain("t".repeat(24)); // the token never goes in the URL
    expect((init.headers as Record<string, string>).Authorization).toBe(`Bearer ${"t".repeat(24)}`);
    expect(URL.createObjectURL).toHaveBeenCalled();
  });

  it("shows the server's message when the download fails, and re-enables the buttons", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ detail: "the scan has not finished" }), { status: 409 })));
    const host = await mount();
    await click(host, "PDF", () => host.querySelector("[role=alert]") !== null);
    expect(host.querySelector("[role=alert]")?.textContent).toBe("the scan has not finished");
    expect([...host.querySelectorAll("button")].every((b) => !b.disabled)).toBe(true);
  });

  it("reports an unreachable API in plain words", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("network"); }));
    const host = await mount();
    await click(host, "HTML", () => host.querySelector("[role=alert]") !== null);
    expect(host.querySelector("[role=alert]")?.textContent).toContain("Cannot reach the Bulwark API");
  });
});
