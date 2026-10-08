// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ComponentsScreen, componentVerdict } from "../components/ComponentsScreen";
import type { ComponentSearch, LibrarySummary } from "../lib/types";

vi.mock("next/navigation", () => ({ usePathname: () => "/app", useRouter: () => ({ push: vi.fn() }) }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core";
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
let root: Root | null = null;
const flush = (ms = 40) => act(async () => { await new Promise((r) => setTimeout(r, ms)); });
afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
  window.history.replaceState(null, "", "/");
});
const AXE = { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } };

const LIB: LibrarySummary = { id: "l1", ecosystem: "maven", name: "org.apache.logging.log4j:log4j-core", purl: LOG4J, projects: 3, versions: 3 };
const RESULT: ComponentSearch = {
  library: LIB, constraint: "<2.17.1",
  summary: { projects: 2, portfolios: 1, internet_facing: 1, exposure_unset: 1, imported_by_app: 1, direct: 0, versions: 2 },
  versions: [
    { version: "2.14.1", projects: 1, matches: true },
    { version: "2.0-beta9", projects: 1, matches: true },
    { version: "2.17.1", projects: 1, matches: false },
  ],
  uses: [
    { project_id: "p1", project: "payments-api", portfolio: "Payments", version: "2.14.1", relation: "transitive",
      paths: ["pom.xml", "sub/pom.xml"], reachable: true, reachable_reason: "Imported by application code (App.java)",
      exposure: "internet", source: "scan", scan_id: "s1", seen_at: "2026-10-01T10:00:00Z" },
    { project_id: "p2", project: "reporting-svc", portfolio: null, version: "2.0-beta9", relation: "direct",
      paths: [], reachable: null, reachable_reason: "", exposure: "unset", source: "test:t1", scan_id: "s2", seen_at: "2026-10-02T10:00:00Z" },
  ],
  uncomparable: [], truncated: false, elapsed_ms: 12.4,
};

describe("the verdict", () => {
  it("says where, how exposed, and how used -- or that nothing matched", () => {
    expect(componentVerdict(RESULT, LOG4J)).toBe(
      "org.apache.logging.log4j:log4j-core <2.17.1 is in 2 projects across 1 business unit: 1 internet-facing (1 not set), 1 importing it from application code.",
    );
    const none = { ...RESULT, uses: [], summary: { ...RESULT.summary, projects: 0 }, versions: [{ version: "2.17.1", projects: 4, matches: false }] };
    expect(componentVerdict(none, LOG4J)).toBe("No project uses org.apache.logging.log4j:log4j-core <2.17.1. 4 projects use other versions.");
    expect(componentVerdict({ ...RESULT, library: null }, "pkg:npm/left-pad")).toBe("No project's SBOM lists pkg:npm/left-pad.");
  });
});

describe("the components screen", () => {
  it("searches from the URL, shows every use, and is accessible", async () => {
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      const u = new URL(String(url));
      calls.push(u.pathname + u.search);
      if (u.pathname === "/v2/libraries") return json([LIB]);
      if (u.pathname === "/v2/components") return json({ ...RESULT, uncomparable: ["2.x-weird"] });
      return json({}, 404);
    }));
    const host = document.createElement("div");
    document.body.replaceChildren(host);
    root = createRoot(host);
    await act(async () => root!.render(<ComponentsScreen initialPurl={LOG4J} initialVersion="<2.17.1" />));
    await flush();
    expect(calls).toContain(`/v2/components?purl=${encodeURIComponent(LOG4J)}&version=%3C2.17.1`);
    expect(host.querySelector(".ds-comp-verdict")?.textContent).toContain("is in 2 projects");
    expect(host.querySelector(".ds-comp-warn")?.textContent).toBe("1 version could not be compared with <2.17.1 and is not counted: 2.x-weird.");
    const rows = Array.from(host.querySelectorAll(".ds-comp-table tbody tr"));
    expect(rows.map((r) => r.querySelector("th a")?.textContent)).toEqual(["payments-api", "reporting-svc"]);
    expect(rows[0]!.textContent).toContain("pom.xml +1 more");
    expect(rows[1]!.textContent).toContain("Can't tell");
    expect(rows[1]!.textContent).toContain("Not set");
    expect(window.location.search).toBe(`?purl=${encodeURIComponent(LOG4J)}&version=%3C2.17.1`);
    expect(host.textContent).not.toContain("Most used"); // an answer replaces the list
    const results = await axe.run(host, AXE);
    expect(results.violations.map((v) => v.id)).toEqual([]);
  });

  it("searching a library's short name at once opens it, without waiting for the suggestions", async () => {
    // Week 74 (J7): pressing Search before the suggestions arrived said "No library in use is
    // named like log4j-core" above the very library -- the screen's own placeholder example.
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      const u = new URL(String(url));
      calls.push(u.pathname + u.search);
      if (u.pathname === "/v2/libraries") return json(u.searchParams.get("q") ? [LIB, { ...LIB, id: "l3", name: "org.example:log4j-core-shim", purl: "pkg:maven/org.example/log4j-core-shim" }] : []);
      if (u.pathname === "/v2/components") return json(RESULT);
      return json({}, 404);
    }));
    const host = document.createElement("div");
    document.body.replaceChildren(host);
    root = createRoot(host);
    await act(async () => root!.render(<ComponentsScreen />));
    await flush();
    const lib = host.querySelector<HTMLInputElement>("input[id$='-lib']")!;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
    await act(async () => { setter.call(lib, "log4j-core"); lib.dispatchEvent(new Event("input", { bubbles: true })); });
    await act(async () => host.querySelector("form")!.requestSubmit()); // no wait for the 200 ms list
    await flush();
    expect(host.querySelector("[role=alert]")).toBeNull();
    expect(calls).toContain(`/v2/components?purl=${encodeURIComponent(LOG4J)}`);
  });

  it("suggests libraries by name, and a bad version condition is marked on its field", async () => {
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      const u = new URL(String(url));
      calls.push(u.pathname + u.search);
      if (u.pathname === "/v2/libraries") return json(u.searchParams.get("q") ? [LIB] : [LIB, { ...LIB, id: "l2", name: "lodash", purl: "pkg:npm/lodash", ecosystem: "npm" }]);
      if (u.pathname === "/v2/components") {
        if (u.searchParams.get("version") === "<<1") return json({ detail: { field: "version", message: "'<<1' is not a version condition such as <2.17.1" } }, 422);
        return json(RESULT);
      }
      return json({}, 404);
    }));
    const host = document.createElement("div");
    document.body.replaceChildren(host);
    root = createRoot(host);
    await act(async () => root!.render(<ComponentsScreen />));
    await flush();
    expect(Array.from(host.querySelectorAll(".ds-comp-top .ds-comp-name")).map((n) => n.textContent)).toEqual([LIB.name, "lodash"]);
    const lib = host.querySelector<HTMLInputElement>("input[id$='-lib']")!;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
    await act(async () => { setter.call(lib, "log4j"); lib.dispatchEvent(new Event("input", { bubbles: true })); });
    await flush(260);
    expect(calls).toContain("/v2/libraries?q=log4j&limit=8");
    const suggestion = host.querySelector<HTMLButtonElement>(".ds-comp-suggest button")!;
    expect(suggestion.textContent).toContain("3 projects, 3 versions");
    const ver = host.querySelector<HTMLInputElement>("input[id$='-ver']")!;
    await act(async () => { setter.call(ver, "<<1"); ver.dispatchEvent(new Event("input", { bubbles: true })); });
    await act(async () => suggestion.click());
    await flush();
    expect(host.querySelector("[role=alert]")?.textContent).toContain("not a version condition");
    expect(ver.getAttribute("aria-invalid")).toBe("true");
    expect(lib.value).toBe(LOG4J);
  });
});
