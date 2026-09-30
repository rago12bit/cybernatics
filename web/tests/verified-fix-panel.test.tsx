// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { VerifiedFixPanel } from "../components/VerifiedFixPanel";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | null = null;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const AWAITING_APPROVAL = {
  run_id: "run1",
  issue_id: "issue1",
  status: "awaiting_approval",
  attempts: 2,
  latest_patch: {
    explanation: "Use a parameterized query.",
    patch: "--- a/app/users.py\n+++ b/app/users.py\n@@ -1,2 +1,2 @@\n-old line\n+new line\n",
    confidence: "high",
    tokens_used: 500,
  },
  verification_record: [
    { attempt: 1, steps: [{ name: "rerun_rule", passed: false, detail: "bandit still flags this" }], feedback: "bandit still flags this" },
    {
      attempt: 2,
      steps: [
        { name: "rerun_rule", passed: true, detail: "bandit no longer flags this finding" },
        { name: "rerun_scanners", passed: true, detail: "no new findings on the changed file(s)" },
      ],
    },
  ],
  ended_reason: null,
  pr_url: null,
  created_at: "2026-09-30T00:00:00Z",
  updated_at: "2026-09-30T00:05:00Z",
};

async function mount(assetId = "a1", issueId = "i1") {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<VerifiedFixPanel assetId={assetId} issueId={issueId} />));
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

describe("VerifiedFixPanel", () => {
  it("offers to start a fix when none has run yet", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json({ detail: "no verified-fix run for this issue" }, 404)));
    const host = await mount();
    expect(host.textContent).toContain("Try a verified fix");
  });

  it("shows the verification record before the diff, and both attempts' history", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(AWAITING_APPROVAL)));
    const host = await mount();
    const text = host.textContent ?? "";
    const verificationIdx = text.indexOf("Verification");
    const diffIdx = text.indexOf("new line");
    expect(verificationIdx).toBeGreaterThanOrEqual(0);
    expect(diffIdx).toBeGreaterThan(verificationIdx); // "trust before content" (plan §28.4)
    expect(text).toContain("Took 2 attempts");
    expect(text).toContain("bandit still flags this");
  });

  it("renders the diff with real -/+ lines", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(AWAITING_APPROVAL)));
    const host = await mount();
    const adds = Array.from(host.querySelectorAll(".d-add")).map((el) => el.textContent);
    const dels = Array.from(host.querySelectorAll(".d-del")).map((el) => el.textContent);
    expect(adds).toContain("+new line");
    expect(dels).toContain("-old line");
  });

  it("offers Reject and Open pull request only while awaiting approval", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(AWAITING_APPROVAL)));
    const host = await mount();
    const buttons = Array.from(host.querySelectorAll("button")).map((b) => b.textContent);
    expect(buttons).toContain("Reject");
    expect(buttons).toContain("Open pull request");
  });

  it("approving calls the approve endpoint and reloads", async () => {
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        calls.push(`${init?.method ?? "GET"} ${url}`);
        if (init?.method === "POST" && url.endsWith("/approve")) return json({ status: "approved" });
        if (calls.filter((c) => c.startsWith("GET")).length > 1) {
          return json({ ...AWAITING_APPROVAL, status: "opened_pr", pr_url: "https://github.com/acme/x/pull/1" });
        }
        return json(AWAITING_APPROVAL);
      }),
    );
    const host = await mount("a1", "i1");
    const openPrButton = Array.from(host.querySelectorAll("button")).find((b) => b.textContent === "Open pull request")!;
    await act(async () => openPrButton.click());
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50));
    });
    expect(calls.some((c) => c.includes("/approve"))).toBe(true);
    expect(host.textContent).toContain("Pull request opened");
    expect(host.querySelector("a")?.getAttribute("href")).toBe("https://github.com/acme/x/pull/1");
  });

  it("shows an inconclusive result as distinct from a failure, per ADR-0015", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        json({ ...AWAITING_APPROVAL, status: "inconclusive", ended_reason: "overall_timeout", latest_patch: null }),
      ),
    );
    const host = await mount();
    expect(host.textContent).toMatch(/not evidence the fix is wrong/);
  });

  it("offers to start a fresh run after a failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => json({ ...AWAITING_APPROVAL, status: "failed", ended_reason: "max_attempts_exhausted", latest_patch: null })),
    );
    const host = await mount();
    expect(Array.from(host.querySelectorAll("button")).map((b) => b.textContent)).toContain("Try again");
  });

  it("starting a fix posts to the start endpoint", async () => {
    let posted = false;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method === "POST") {
          posted = true;
          return json({ run_id: "r1", workflow_id: "wf-1" });
        }
        return json({ detail: "no run" }, 404);
      }),
    );
    const host = await mount();
    const startButton = Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.includes("Try a verified fix"))!;
    await act(async () => startButton.click());
    expect(posted).toBe(true);
  });
});
