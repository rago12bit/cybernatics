// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DependenciesView } from "../components/DependenciesView";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | null = null;

const view = {
  scan_id: "s1",
  generated_at: "2026-09-30T00:00:00Z",
  components: 3,
  ecosystems: { pypi: 3 },
  packages: [
    {
      name: "myproject", version: "1.0.0", ecosystem: "pypi", purl: "pkg:pypi/myproject@1.0.0",
      license: "", path: "requirements.txt", relation: "root", depends_on: ["pkg:pypi/flask@2.0.0"],
      scorecard: null,
    },
    {
      name: "flask", version: "2.0.0", ecosystem: "pypi", purl: "pkg:pypi/flask@2.0.0",
      license: "BSD-3-Clause", path: "requirements.txt", relation: "direct",
      depends_on: ["pkg:pypi/werkzeug@2.0.0"],
      scorecard: { score: 8.3, checks: { Maintained: 10 }, date: "2026-09-28" },
    },
    {
      name: "werkzeug", version: "2.0.0", ecosystem: "pypi", purl: "pkg:pypi/werkzeug@2.0.0",
      license: "", path: "requirements.txt", relation: "transitive", depends_on: [], scorecard: null,
    },
  ],
};  // fmt: skip

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

async function mount() {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<DependenciesView assetId="a1" />));
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

describe("DependenciesView", () => {
  it("renders every package with its relation and license", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(view)));
    const host = await mount();
    expect(host.textContent).toContain("flask");
    expect(host.textContent).toContain("werkzeug");
    expect(host.textContent).toContain("BSD-3-Clause");
    expect(host.textContent).toContain("8.3"); // flask's Scorecard score
  });

  it("says so when there is no SBOM yet, instead of an empty table", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json({ scan_id: null, generated_at: null, components: 0, ecosystems: {}, packages: [] })));
    const host = await mount();
    expect(host.textContent).toMatch(/No SBOM for this project yet/);
  });

  it("shows a readable error when the request fails", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ detail: "not found" }), { status: 404 })));
    const host = await mount();
    expect(host.querySelector("[role=alert]")?.textContent).toBe("not found");
  });

  it("filters by name and by relation", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(view)));
    const host = await mount();
    const search = host.querySelector("input[type=search]") as HTMLInputElement;
    // React tracks the DOM node's "last known value" itself, so a plain `.value =` assignment is
    // invisible to its change-detection; go through the native setter, same workaround
    // scan-comparison.test.tsx's own <select> case doesn't need but a text input does.
    const setValue = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")!.set!;
    await act(async () => {
      setValue.call(search, "werk");
      search.dispatchEvent(new Event("input", { bubbles: true }));
    });
    expect(host.textContent).toContain("werkzeug");
    expect(host.textContent).not.toContain("flask");
  });

  it("expands a row from the keyboard: its name is a button that says whether it is open", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(view)));
    const host = await mount();
    const toggle = [...host.querySelectorAll<HTMLButtonElement>("button.ds-deps-toggle")].find((b) => b.textContent?.includes("werkzeug"))!;
    expect(toggle).toBeDefined();
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    // Enter or Space on a focused button fires a click; it bubbles to the row once, not twice.
    await act(async () => toggle.click());
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    expect(host.textContent).toContain("Path from root");
  });

  it("expands a row to show its path from root and its dependents", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(view)));
    const host = await mount();
    const row = Array.from(host.querySelectorAll("tr")).find((r) => r.textContent?.includes("werkzeug"));
    await act(async () => {
      row!.dispatchEvent(new Event("click", { bubbles: true }));
    });
    // path: myproject -> flask -> werkzeug
    expect(host.textContent).toContain("myproject");
    expect(host.textContent).toContain("Path from root");
  });
});
