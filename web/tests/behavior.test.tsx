// @vitest-environment jsdom
// Behaviour tests for the interactive UI: live scan updates, sign-in state, the submit form, recent scans.
import { act, useEffect } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RecentScans } from "../components/RecentScans";
import { SubmitForm } from "../components/SubmitForm";
import { TokenGate } from "../components/TokenGate";
import { SiteHeader } from "../components/site/SiteHeader";
import { clearToken, getToken, setToken } from "../lib/api";
import { useScan } from "../lib/useScan";
import type { ScanView } from "../lib/types";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let path = "/app";
const push = vi.fn();
vi.mock("next/navigation", () => ({ usePathname: () => path, useRouter: () => ({ push }) }));

const TOKEN = "t".repeat(24);
const view = (over: Partial<ScanView> = {}): ScanView => ({
  id: "s1", status: "running", source_type: "git", source_label: "repo", tools: ["bandit", "trivy"], created_at: "2026-09-25T00:00:00Z",
  started_at: null, finished_at: null, error: null, tool_status: {}, severity_counts: {}, raw_findings: 0, unique_findings: 0, dedup_rate: 0, ...over,
});
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

class FakeWS {
  static all: FakeWS[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((m: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: ((e: { code: number }) => void) | null = null;
  sent: string[] = [];
  closed = false;
  constructor(public url: string) { FakeWS.all.push(this); }
  send(d: string) { this.sent.push(d); }
  close() { this.closed = true; }
  emit(ev: unknown) { this.onmessage?.({ data: JSON.stringify(ev) }); }
}

let root: Root | null = null;
async function mount(node: React.ReactNode) {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(node));
  return host;
}
const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 0)); });

beforeEach(() => {
  FakeWS.all = [];
  push.mockReset();
  path = "/app";
  vi.stubGlobal("WebSocket", FakeWS);
  sessionStorage.clear();
  setToken(TOKEN);
});
afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  vi.useRealTimers();
  document.body.innerHTML = "";
});

// A probe that exposes the hook's state as text, so tests read what a user would see.
function Probe({ id }: { id: string }) {
  const { scan, error, connection, version } = useScan(id);
  useEffect(() => undefined, [version]);
  return <p id="out">{`${scan?.id ?? "-"}|${scan?.status ?? "-"}|${connection}|v${version}|${error ?? ""}`}</p>;
}
const out = (h: HTMLElement) => h.querySelector("#out")!.textContent;

describe("live scan updates (useScan)", () => {
  it("does not get stuck 'running' when the scan finishes between the first read and the socket connecting", async () => {
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (u: string) => { calls.push(u); return json(view({ status: calls.length === 1 ? "running" : "completed" })); }));
    const h = await mount(<Probe id="s1" />);
    await flush();
    const ws = FakeWS.all[0]!;
    await act(async () => { ws.onopen?.(); ws.emit({ type: "snapshot", ...view({ status: "completed" }) }); ws.onclose?.({ code: 1000 }); });
    await flush();
    expect(out(h)).toContain("|completed|done|");
  });

  it("recovers when the socket closes cleanly but the scan is not finished (missed event)", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let n = 0;
    vi.stubGlobal("fetch", vi.fn(async () => json(view({ status: ++n < 3 ? "running" : "completed" }))));
    const h = await mount(<Probe id="s1" />);
    await flush();
    await act(async () => { FakeWS.all[0]!.onopen?.(); FakeWS.all[0]!.onclose?.({ code: 1000 }); });
    await act(async () => { await vi.advanceTimersByTimeAsync(7000); });
    expect(out(h)).toContain("|completed|done|");
  });

  it("shows the new scan, not the previous one, when the id changes", async () => {
    let resolveB: (r: Response) => void = () => undefined;
    vi.stubGlobal("fetch", vi.fn((u: string) => u.includes("/scans/b") ? new Promise<Response>((r) => { resolveB = r; }) : Promise.resolve(json(view({ id: "a", status: "completed" })))));
    const host = document.createElement("div");
    document.body.replaceChildren(host);
    root = createRoot(host);
    await act(async () => root!.render(<Probe id="a" />));
    await flush();
    expect(out(host)).toContain("a|completed");
    await act(async () => root!.render(<Probe id="b" />));
    expect(out(host)).toMatch(/^-\|-\|connecting/); // not the stale scan "a" under the URL for "b"
    await act(async () => resolveB(json(view({ id: "b", status: "completed" }))));
    await flush();
    expect(out(host)).toContain("b|completed");
  });

  it("polling does not re-trigger result refetches when nothing changed", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.stubGlobal("fetch", vi.fn(async () => json(view({ status: "running" }))));
    const h = await mount(<Probe id="s1" />);
    await flush();
    await act(async () => { FakeWS.all[0]!.onerror?.(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(out(h)).toMatch(/\|polling\|v1\|/); // still version 1 after several identical polls
  });

  it("an expired token ends the session cleanly instead of polling 401s forever", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const fetchMock = vi.fn(async () => json(view({ status: "running" })));
    vi.stubGlobal("fetch", fetchMock);
    const h = await mount(<Probe id="s1" />);
    await flush();
    await act(async () => { FakeWS.all[0]!.onclose?.({ code: 4401 }); });
    const before = fetchMock.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(fetchMock.mock.calls.length).toBe(before); // no polling after unauthorized
    expect(getToken()).toBeNull();
    expect(out(h)).toMatch(/expired|sign in/i);
  });
});

describe("sign-in state", () => {
  it("the header shows Sign out as soon as you sign in (no navigation needed)", async () => {
    clearToken();
    const h = await mount(<SiteHeader />);
    expect(h.textContent).not.toContain("Sign out");
    await act(async () => setToken(TOKEN));
    expect(h.textContent).toContain("Sign out");
    await act(async () => clearToken());
    expect(h.textContent).not.toContain("Sign out");
  });

  it("the app returns to the sign-in screen when the token is cleared mid-session", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json([])));
    const h = await mount(<TokenGate><p id="secret">secret</p></TokenGate>);
    await flush();
    expect(h.querySelector("#secret")).not.toBeNull();
    await act(async () => clearToken());
    expect(h.querySelector("#secret")).toBeNull();
    expect(h.querySelector("label[for=token]")).not.toBeNull();
  });
});

describe("new scan form", () => {
  it("does not submit a file you can no longer see after switching source type", async () => {
    const fetchMock = vi.fn(async () => json({ id: "n1", status: "queued" }, 202));
    vi.stubGlobal("fetch", fetchMock);
    const h = await mount(<SubmitForm />);
    const seg = () => [...h.querySelectorAll<HTMLButtonElement>(".seg button")];
    await act(async () => seg()[1]!.click());
    const input = h.querySelector<HTMLInputElement>("#file")!;
    const file = new File(["x"], "old.zip");
    Object.defineProperty(input, "files", { value: [file], configurable: true });
    await act(async () => { input.dispatchEvent(new Event("change", { bubbles: true })); });
    expect(h.querySelector<HTMLButtonElement>("button.primary")!.disabled).toBe(false);
    await act(async () => seg()[0]!.click());
    await act(async () => seg()[1]!.click()); // back to upload: the picker is empty again
    expect(h.querySelector<HTMLInputElement>("#file")!.value).toBe("");
    expect(h.querySelector<HTMLButtonElement>("button.primary")!.disabled).toBe(true); // nothing chosen, nothing to submit
  });

  it("explains why Start is disabled instead of silently greying out", async () => {
    vi.stubGlobal("fetch", vi.fn());
    const h = await mount(<SubmitForm />);
    const url = h.querySelector<HTMLInputElement>("#url")!;
    const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
    await act(async () => { set.call(url, "github.com/owner/repo"); url.dispatchEvent(new Event("input", { bubbles: true })); });
    expect(h.querySelector("[data-testid=form-hint], .hint")?.textContent ?? "").toMatch(/https:\/\//);
    for (const c of h.querySelectorAll<HTMLInputElement>(".checks input")) await act(async () => c.click());
    expect(h.textContent).toMatch(/at least one scanner/i);
  });
});

describe("recent scans", () => {
  const row = (status: string) => ({ id: "r1", status, source_type: "git", source_label: "repo", created_at: new Date().toISOString(), finished_at: null, unique_findings: 0, severity_counts: {} });
  it("keeps itself up to date while a scan is running, then stops polling", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let n = 0;
    const fetchMock = vi.fn(async () => json([row(++n < 3 ? "running" : "completed")]));
    vi.stubGlobal("fetch", fetchMock);
    const h = await mount(<RecentScans />);
    await flush();
    expect(h.textContent).toContain("running");
    await act(async () => { await vi.advanceTimersByTimeAsync(9000); });
    expect(h.textContent).toContain("completed");
    const settled = fetchMock.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(20_000); });
    expect(fetchMock.mock.calls.length).toBe(settled); // nothing running: no more requests
  });

  it("keeps 'Started … ago' current without a reload", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const created = new Date(Date.now() - 20_000).toISOString();
    vi.stubGlobal("fetch", vi.fn(async () => json([{ ...row("completed"), created_at: created }])));
    const h = await mount(<RecentScans />);
    await flush();
    expect(h.textContent).toContain("just now");
    await act(async () => { await vi.advanceTimersByTimeAsync(5 * 60_000); });
    expect(h.textContent).toMatch(/[45] min ago/);
  });
});
