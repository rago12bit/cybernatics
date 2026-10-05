// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MapperScreen } from "../components/MapperScreen";
import type { AnalyzeResult, MappingPreview, MappingSpec } from "../lib/types";

vi.mock("next/navigation", () => ({ usePathname: () => "/app", useRouter: () => ({ push: vi.fn() }) }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const ASSET = "11111111-1111-4111-8111-111111111111";
const MAPPING = "33333333-3333-4333-8333-333333333333";

const DRAFT: MappingSpec = {
  format: "json", source: "acme-scan", records: "$.issues[*]", category: "sast",
  fields: { title: '$["Issue Name"]', severity: "$.Risk", path: "$.Location.File" },
  severity_map: { p1: "CRITICAL" },
};

function analysis(proposedBy = "heuristic", notes: string[] = []): AnalyzeResult {
  return {
    analysis: {
      format: "json",
      error: null,
      candidates: [
        { records: "$.issues[*]", count: 2, fields: [
          { path: '$["Issue Name"]', examples: ["SQL injection", "XSS"], filled: 2 },
          { path: "$.Risk", examples: ["P1", "amber"], filled: 2 },
          { path: "$.Location.File", examples: ["a.py", "b.js"], filled: 2 },
          { path: "$.PluginID", examples: ["AC-1", "AC-2"], filled: 2 },
        ] },
        { records: "$.meta.tags[*]", count: 1, fields: [{ path: "$.a", examples: ["1"], filled: 1 }] },
      ],
    },
    proposal: { spec: DRAFT, proposed_by: proposedBy, notes },
    sample_digest: "d".repeat(64),
    suggested_source: "acme-scan",
    model_available: proposedBy.startsWith("model:"),
    fields: ["title", "severity", "description", "path", "line", "rule", "cwe", "cve", "url", "package",
      "version", "ecosystem", "recommendation", "references"],
  };
}

const PREVIEW: MappingPreview = {
  total: 2,
  issues: [
    { title: "SQL injection", severity: "CRITICAL", native_severity: "P1", category: "sast",
      location: "a.py:1", cwe: ["CWE-89"], cve: [], rule: null },
    { title: "XSS", severity: "INFO", native_severity: "AMBER", category: "sast", location: "b.js:1",
      cwe: [], cve: [], rule: null },
  ],
  by_severity: { CRITICAL: 1, INFO: 1 },
  warnings: ["1 finding(s) use the severity 'amber', which is not a known severity; imported as Info"],
  error: null,
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

type Call = { method: string; path: string; form?: FormData; body?: unknown };

function api(o: { analyze?: AnalyzeResult; preview?: (spec: MappingSpec) => Response } = {}) {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const path = new URL(String(url)).pathname;
    const method = init?.method ?? "GET";
    const form = init?.body instanceof FormData ? init.body : undefined;
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ method, path, form, body });
    if (path === "/v2/mappings/analyze") return json(o.analyze ?? analysis());
    if (path === "/v2/mappings/preview") {
      const spec = JSON.parse(String(form!.get("spec"))) as MappingSpec;
      return o.preview ? o.preview(spec) : json(PREVIEW);
    }
    if (path === "/v2/mappings" && method === "POST")
      return json({ id: MAPPING, parser: `universal:${MAPPING}`, name: body.name, version: 1,
        source: body.spec.source, format: "json", spec: body.spec, proposed_by: body.proposed_by,
        created_at: "2026-10-05T00:00:00Z", created_by: "t", versions: [] }, 201);
    return json({}, 404);
  }));
  return calls;
}

let root: Root | null = null;
const flush = (ms = 40) => act(async () => { await new Promise((r) => setTimeout(r, ms)); });

async function mount() {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(<MapperScreen assetId={ASSET} />));
  return host;
}

async function upload(host: HTMLElement) {
  const input = host.querySelector("#map-file") as HTMLInputElement;
  const file = new File(['{"issues":[]}'], "acme-scan.json", { type: "application/json" });
  Object.defineProperty(input, "files", { value: [file], configurable: true });
  await act(async () => input.dispatchEvent(new Event("change", { bubbles: true })));
  await flush(40);
  await flush(500); // the preview runs after the mapping settles
}

const byLabel = (host: HTMLElement, text: string) => {
  const label = Array.from(host.querySelectorAll("label")).find((l) => l.textContent?.trim().startsWith(text));
  return host.querySelector(`#${CSS.escape(label!.htmlFor)}`) as HTMLInputElement | HTMLSelectElement;
};

async function typeInto(el: HTMLInputElement | HTMLSelectElement, value: string) {
  const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(el, value);
  await act(async () => el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? "change" : "input", { bubbles: true })));
}

const button = (host: HTMLElement, text: string) =>
  Array.from(host.querySelectorAll("button")).find((b) => b.textContent?.trim() === text) as HTMLButtonElement;

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("MapperScreen", () => {
  it("sends the sample for a draft, asking for the model by default", async () => {
    const calls = api();
    const host = await mount();
    await upload(host);
    const post = calls.find((c) => c.path === "/v2/mappings/analyze")!;
    expect(post.form!.get("use_model")).toBe("true");
    expect((post.form!.get("file") as File).name).toBe("acme-scan.json");
  });

  it("shows the draft for review, says who drafted it, and fills every field from it", async () => {
    api({ analyze: analysis("model:claude-x", ["Ignored from the model's draft: rule -> '$.Nope'."]) });
    const host = await mount();
    await upload(host);
    expect(host.textContent).toContain("Draft — review every field before saving.");
    expect(host.textContent).toContain("drafted by a model (claude-x)");
    expect(host.querySelector(".ds-map-ai")?.textContent?.trim()).toBe("AI suggestion");
    expect(host.textContent).toContain("Ignored from the model's draft");
    expect(byLabel(host, "Title").value).toBe('$["Issue Name"]');
    expect(byLabel(host, "Severity").value).toBe("$.Risk");
    expect(byLabel(host, "Rule or check ID").value).toBe("");
    expect(byLabel(host, "Mapping name").value).toBe("acme-scan");
  });

  it("previews on the server and shows its counts and rows, not its own", async () => {
    api();
    const host = await mount();
    await upload(host);
    expect(host.querySelector(".ds-map-total")!.textContent).toContain("This mapping makes 2 issues from the sample: 1 critical, 1 info.");
    const rows = Array.from(host.querySelectorAll(".ds-map-preview tbody tr"));
    expect(rows.map((r) => r.querySelector("td")!.textContent)).toEqual(["SQL injection", "XSS"]);
    expect(host.textContent).toContain("'amber'");
  });

  it("re-previews with the edited mapping, including the severity meanings", async () => {
    const calls = api();
    const host = await mount();
    await upload(host);
    await typeInto(byLabel(host, "Rule or check ID") as HTMLInputElement, "$.PluginID");
    await typeInto(byLabel(host, "amber") as HTMLSelectElement, "MEDIUM");
    await flush(500);
    const last = calls.filter((c) => c.path === "/v2/mappings/preview").at(-1)!;
    const spec = JSON.parse(String(last.form!.get("spec"))) as MappingSpec;
    expect(spec.fields.rule).toBe("$.PluginID");
    expect(spec.severity_map).toEqual({ p1: "CRITICAL", amber: "MEDIUM" });
  });

  it("saves the reviewed mapping with who drafted it, and says how to use it", async () => {
    const calls = api();
    const host = await mount();
    await upload(host);
    await typeInto(byLabel(host, "Mapping name") as HTMLInputElement, "Acme scanner");
    await act(async () => button(host, "Save mapping").click());
    await flush();
    const post = calls.find((c) => c.path === "/v2/mappings" && c.method === "POST")!;
    expect(post.body).toMatchObject({ name: "Acme scanner", spec: DRAFT, proposed_by: "heuristic",
      sample_digest: "d".repeat(64) });
    expect(host.querySelector(".ds-map-done")!.textContent).toContain("Saved Acme scanner as version 1");
    expect(host.textContent).toContain(`universal:${MAPPING}`);
  });

  it("will not save a mapping the preview cannot read the sample with", async () => {
    api({ preview: () => json({ ...PREVIEW, total: 0, issues: [], by_severity: {}, warnings: [],
      error: "no `issues` list found" }) });
    const host = await mount();
    await upload(host);
    expect(host.textContent).toContain("could not be read with this mapping: no `issues` list found");
    expect(button(host, "Save mapping").disabled).toBe(true);
  });

  it("shows the server's refusal of an invalid mapping instead of a preview", async () => {
    api({ preview: () => json({ detail: "the records path must end in `[*]`" }, 422) });
    const host = await mount();
    await upload(host);
    expect(host.querySelector("[role=alert]")!.textContent).toContain("must end in `[*]`");
    expect(button(host, "Save mapping").disabled).toBe(true);
  });

  it("has no accessibility violations with a draft and a preview on screen", async () => {
    api();
    const host = await mount();
    await upload(host);
    const r = await axe.run(host, { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } });
    expect(r.violations.map((v) => v.id)).toEqual([]);
  });
});
