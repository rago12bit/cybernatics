// @vitest-environment jsdom
// The app's "Connecting" screen: it says what it is waiting on, and never waits forever.
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let host: HTMLDivElement;
let root: Root;

async function mountGate() {
  vi.resetModules(); // each test starts with no cached session check
  const { TokenGate } = await import("../components/TokenGate");
  await act(async () => root.render(<TokenGate><p>the app</p></TokenGate>));
}

beforeEach(() => {
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});
afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("connecting to the API", () => {
  it("after a few seconds without an answer, names the API it is waiting on and offers to try again", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>(() => {})));
    await mountGate();
    expect(host.textContent).toContain("Connecting");
    expect(host.textContent).not.toContain("has not answered");
    await act(async () => { vi.advanceTimersByTime(5000); });
    expect(host.textContent).toContain("http://localhost:8000");
    expect(host.textContent).toContain("has not answered yet");
    expect([...host.querySelectorAll("button")].map((b) => b.textContent)).toContain("Try again");
  });

  it("gives the session check a deadline, and an API that never answers ends at sign-in", async () => {
    // Like a real fetch to an API that accepts the connection and never answers: only the deadline ends it.
    const fetch = vi.fn((_u: string, init?: RequestInit) => new Promise<Response>((_, reject) => {
      const stop = () => reject(new DOMException("timed out", "TimeoutError"));
      if (init?.signal?.aborted) stop();
      else init?.signal?.addEventListener("abort", stop);
    }));
    vi.stubGlobal("fetch", fetch);
    const timeout = vi.spyOn(AbortSignal, "timeout").mockImplementation(() => AbortSignal.abort(new DOMException("timed out", "TimeoutError")));
    await mountGate();
    await act(async () => {});
    expect(timeout).toHaveBeenCalledWith(10_000);
    expect(fetch.mock.calls[0]![1]!.signal).toBeDefined();
    expect(host.textContent).not.toContain("Connecting");
    expect(host.textContent).not.toContain("the app");
  });
});
