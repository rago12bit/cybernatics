// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { TriageAssistantPanel } from "../components/TriageAssistantPanel";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | null = null;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const VERDICT = {
  verdict: "likely_false_positive",
  confidence: "high",
  rationale: "The input is parameterized before reaching the sink.",
  supporting_lines: [10, 11],
  model: "claude-sonnet-5",
  generated_at: "2026-09-30T00:00:00Z",
};

async function mount(assetId = "a1", issueId = "i1") {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<TriageAssistantPanel assetId={assetId} issueId={issueId} />));
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
  return host;
}

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("TriageAssistantPanel", () => {
  it("offers to get a verdict when none exists yet", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json({ detail: "no verdict yet" }, 404)));
    const host = await mount();
    expect(host.textContent).toContain("Get a triage verdict");
  });

  it("shows the verdict, confidence, rationale, and supporting lines", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(VERDICT)));
    const host = await mount();
    const text = host.textContent ?? "";
    expect(text).toContain("Likely false positive");
    expect(text).toContain("high confidence");
    expect(text).toContain("parameterized before reaching the sink");
    expect(text).toContain("10, 11");
  });

  it("never claims to change the issue's status", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(VERDICT)));
    const host = await mount();
    expect(host.textContent).toMatch(/does not change the issue.s status/);
  });

  it("requesting a verdict posts to the triage-assistant endpoint", async () => {
    let posted = false;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method === "POST" && url.includes("/triage-assistant")) {
          posted = true;
          return json(VERDICT);
        }
        return json({ detail: "no verdict yet" }, 404);
      }),
    );
    const host = await mount();
    const button = Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.includes("Get a triage verdict"))!;
    await act(async () => button.click());
    expect(posted).toBe(true);
  });

  it("shows an error message when the request fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method === "POST") return json({ detail: "the triage assistant is not enabled on this server" }, 409);
        return json({ detail: "no verdict yet" }, 404);
      }),
    );
    const host = await mount();
    const button = Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.includes("Get a triage verdict"))!;
    await act(async () => button.click());
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50));
    });
    expect(host.textContent).toContain("not enabled on this server");
  });
});
