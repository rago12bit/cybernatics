// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CampaignsView } from "../components/CampaignsView";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | null = null;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function mount() {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<CampaignsView assetId="a1" />));
  await act(async () => {
    await new Promise((r) => setTimeout(r, 20));
  });
  return host;
}

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("CampaignsView", () => {
  it("shows an empty state when there are no campaigns yet", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json([])));
    const host = await mount();
    expect(host.textContent).toContain("No campaigns yet.");
  });

  it("lists past campaigns with a link to their scan report", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        json([
          {
            id: "s1", status: "completed", source_type: "web", source_label: "example.com",
            created_at: "2026-10-01T00:00:00Z", finished_at: "2026-10-01T00:05:00Z",
            unique_findings: 7, severity_counts: {},
          },
        ]),
      ),
    );
    const host = await mount();
    expect(host.textContent).toContain("completed");
    expect(host.textContent).toContain("7");
    const link = host.querySelector('a[href="/scans/s1"]');
    expect(link).not.toBeNull();
  });

  it("starting a passive campaign posts mode=passive and refreshes the list", async () => {
    let posted: unknown = null;
    let getCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method === "POST") {
          posted = JSON.parse(init.body as string);
          return json({ id: "s2", status: "queued" });
        }
        getCalls += 1;
        return json([]);
      }),
    );
    const host = await mount();
    const btn = Array.from(host.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("Start passive scan"),
    )!;
    await act(async () => btn.click());
    await act(async () => {
      await new Promise((r) => setTimeout(r, 20));
    });
    expect(posted).toMatchObject({ mode: "passive" });
    expect(getCalls).toBeGreaterThanOrEqual(2); // initial load + refresh after starting
  });

  it("shows an error when starting a campaign fails (e.g. rate limited)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method === "POST") {
          return json({ detail: "active scan rate limit: try again in 23.0h" }, 429);
        }
        return json([]);
      }),
    );
    const host = await mount();
    const btn = Array.from(host.querySelectorAll("button")).find((b) =>
      b.textContent?.includes("Start active scan"),
    )!;
    await act(async () => btn.click());
    await act(async () => {
      await new Promise((r) => setTimeout(r, 20));
    });
    expect(host.querySelector('[role="alert"]')).not.toBeNull();
  });
});
