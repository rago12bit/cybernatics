// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HypothesesLane } from "../components/HypothesesLane";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | null = null;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const OPEN_HYPOTHESIS = {
  id: "h1",
  route_method: "DELETE",
  route_path: "/users/<id>",
  file: "app.py",
  line: 20,
  evidence: "No auth decorator, unlike the sibling route.",
  suggested_check: "Call it without a session and see if it still works.",
  confidence: "medium",
  model: "claude-sonnet-5",
  status: "open",
  promoted_issue_id: null,
  created_at: "2026-09-30T00:00:00Z",
};

async function mount(assetId = "a1") {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<HypothesesLane assetId={assetId} />));
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

describe("HypothesesLane", () => {
  it("explains the feature and offers Generate when the list is empty", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json([])));
    const host = await mount();
    expect(host.textContent).toContain("Nothing here yet");
    expect(host.textContent).toContain("Off by default");
  });

  it("lists open hypotheses with evidence and a suggested check", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json([OPEN_HYPOTHESIS])));
    const host = await mount();
    const text = host.textContent ?? "";
    expect(text).toContain("DELETE /users/<id>");
    expect(text).toContain("No auth decorator");
    expect(text).toContain("Call it without a session");
  });

  it("generating calls the generate endpoint and reloads the list", async () => {
    let generated = false;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method === "POST" && url.includes("/generate")) {
          generated = true;
          return json({ generated: 1, hypotheses: [OPEN_HYPOTHESIS] });
        }
        return json(generated ? [OPEN_HYPOTHESIS] : []);
      }),
    );
    const host = await mount();
    const button = Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.includes("Generate"))!;
    await act(async () => button.click());
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50));
    });
    expect(generated).toBe(true);
    expect(host.textContent).toContain("DELETE /users/<id>");
  });

  it("promoting calls the promote endpoint and shows it as confirmed", async () => {
    let promoted = false;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method === "POST" && url.includes("/promote")) {
          promoted = true;
          return json({ issue_id: "iss-9" });
        }
        return json(promoted ? [{ ...OPEN_HYPOTHESIS, status: "promoted", promoted_issue_id: "iss-9" }] : [OPEN_HYPOTHESIS]);
      }),
    );
    const host = await mount();
    const button = Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.includes("Confirm"))!;
    await act(async () => button.click());
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50));
    });
    expect(host.textContent).toContain("view the issue");
  });

  it("dismissing calls the dismiss endpoint", async () => {
    let dismissed = false;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method === "POST" && url.includes("/dismiss")) {
          dismissed = true;
          return json({ status: "dismissed" });
        }
        return json([OPEN_HYPOTHESIS]);
      }),
    );
    const host = await mount();
    const button = Array.from(host.querySelectorAll("button")).find((b) => b.textContent === "Dismiss")!;
    await act(async () => button.click());
    expect(dismissed).toBe(true);
  });
});
