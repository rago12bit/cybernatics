// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FindingDetail } from "../components/FindingDetail";
import { FindingGuidance } from "../components/FindingGuidance";
import { ApiError } from "../lib/api";
import type { Finding, Guidance, GuidanceApi, Remediation, ScanView } from "../lib/types";
import demo from "../lib/demo-data.json";
import demoGuidance from "../lib/demo-guidance.json";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
let root: Root | null = null;

const STATIC: Remediation = {
  source: "static", label: "Reference guidance (not AI-generated)", explanation: "The product builds an SQL command from input.",
  impact: "See the CWE entry.", fix_summary: "Use prepared statements.", suggested_patch: null, confidence: "low", model: null,
  degraded_reason: "reference guidance", warnings: [], patch_status: null, references: [{ title: "CWE-89", url: "https://cwe.mitre.org/data/definitions/89.html" }],
  from_cache: false, generated_at: null,
};
const PATCH = "--- a/app/users.py\n+++ b/app/users.py\n@@ -1,2 +1,2 @@\n def get(uid):\n-    return q + uid\n+    return q, (uid,)\n";
const AI: Remediation = {
  ...STATIC, source: "ai", label: "AI suggestion: review before applying", explanation: "Input can change the query.", impact: "Data could be read.",
  fix_summary: "Bind parameters.", suggested_patch: PATCH, confidence: "medium", model: "some-model-1", degraded_reason: null,
};
const guidance = (over: Partial<Guidance> = {}): Guidance => ({ finding_id: "f1", static: STATIC, ai: null, ai_enabled: true, model: "some-model-1", ...over });
const apiOf = (g: Guidance | Error, req?: () => Promise<Remediation>): GuidanceApi & { get: ReturnType<typeof vi.fn>; request: ReturnType<typeof vi.fn> } => ({
  get: vi.fn(async () => { if (g instanceof Error) throw g; return g; }),
  request: vi.fn(req ?? (async () => AI)),
});

async function mount(node: React.ReactNode) {
  const host = document.createElement("div");
  document.body.replaceChildren(host);
  root = createRoot(host);
  await act(async () => root!.render(node));
  await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
  return host;
}
const view = (api: GuidanceApi, id = "f1") => <FindingGuidance scanId="s1" findingId={id} api={api} />;
const clickButton = async (host: HTMLElement, text: RegExp) =>
  act(async () => { [...host.querySelectorAll("button")].find((b) => text.test(b.textContent ?? ""))!.click(); await new Promise((r) => setTimeout(r, 0)); });
async function axeIssues(host: Element) {
  const r = await axe.run(host, { rules: { "color-contrast": { enabled: false }, region: { enabled: false } } });
  return r.violations.map((v) => `${v.id}: ${v.nodes[0]?.target.join(" ")}`);
}
afterEach(async () => { await act(async () => root?.unmount()); root = null; document.body.innerHTML = ""; });

describe("fix guidance", () => {
  it("shows reference guidance labelled as not AI-generated, and says AI is off when the server has no model", async () => {
    const api = apiOf(guidance({ ai_enabled: false, model: null }));
    const h = await mount(view(api));
    expect(h.textContent).toContain("Reference guidance (not AI-generated)");
    expect(h.textContent).toContain("Use prepared statements.");
    expect(h.textContent).toMatch(/AI suggestions are off/);
    expect(h.querySelector("button")).toBeNull();
    expect(api.request).not.toHaveBeenCalled();
    expect(h.querySelector("a[href='https://cwe.mitre.org/data/definitions/89.html']")).not.toBeNull();
  });

  it("never contacts the model on its own: opening a finding only reads guidance", async () => {
    const api = apiOf(guidance());
    const h = await mount(view(api));
    expect(api.get).toHaveBeenCalledWith("s1", "f1");
    expect(api.request).not.toHaveBeenCalled();
    const consent = h.querySelector("#ai-consent")!.textContent!;
    expect(consent).toMatch(/Sends this finding/);
    expect(consent).toContain("some-model-1");
    expect(consent).toMatch(/only when you click/);
    expect(consent).toMatch(/secrets removed/);
  });

  it("generates on click, then labels the result unmistakably as an AI suggestion to review", async () => {
    const api = apiOf(guidance());
    const h = await mount(view(api));
    await clickButton(h, /Generate AI suggestion/);
    expect(api.request).toHaveBeenCalledTimes(1);
    expect(api.request).toHaveBeenCalledWith("s1", "f1");
    const ai = h.querySelector("[aria-label='AI suggestion']")!;
    expect(ai.textContent).toContain("AI suggestion");
    expect(ai.textContent).toContain("Review before applying.");
    expect(ai.textContent).toContain("Written by some-model-1");
    expect(ai.textContent).toContain("confidence in this fix: medium");
    expect(ai.textContent).toContain("Bulwark never applies patches");
    expect(h.querySelector(".guide.static")).not.toBeNull(); // the reference text stays alongside it
    expect(h.querySelector("button")?.textContent).not.toMatch(/apply/i); // there is no apply button, only copy
    expect(h.textContent).not.toMatch(/Generate AI suggestion/); // one generation per open finding
  });

  it("marks each diff line by its first character, as text", async () => {
    const h = await mount(view(apiOf(guidance({ ai: AI }))));
    const lines = h.querySelector(".diff code")!;
    expect([...lines.querySelectorAll(".d-add")].map((n) => n.textContent)).toEqual(["+++ b/app/users.py", "+    return q, (uid,)"]);
    expect([...lines.querySelectorAll(".d-del")].map((n) => n.textContent)).toEqual(["--- a/app/users.py", "-    return q + uid"]);
    expect(lines.querySelector(".d-hunk")?.textContent).toBe("@@ -1,2 +1,2 @@");
    expect(lines.textContent).toBe(PATCH); // every character is kept, in order
  });

  it("shows a cached suggestion immediately with its provenance, and no generate button", async () => {
    const api = apiOf(guidance({ ai: { ...AI, from_cache: true, warnings: ["The cached patch was written for a different file or line, so it is not shown; the explanation applies."], suggested_patch: null } }));
    const h = await mount(view(api));
    expect(h.textContent).toContain("reused from an earlier identical finding");
    expect(h.textContent).toContain("cached patch was written for a different file");
    expect(h.querySelector(".patch")).toBeNull();
    expect(h.textContent).not.toMatch(/Generate AI suggestion/);
    expect(api.request).not.toHaveBeenCalled();
  });

  it("renders hostile model output as plain text and refuses non-https links", async () => {
    const evil: Remediation = {
      ...AI, explanation: "<img src=x onerror=alert(1)> explanation", impact: "<script>alert(1)</script>", fix_summary: "<b>bold</b>",
      suggested_patch: "--- a/app/users.py\n+++ b/app/users.py\n@@ -1 +1 @@\n-<img src=x onerror=alert(2)>\n+<script>alert(3)</script>\n",
      warnings: ["<iframe src=//evil>"], references: [{ title: "<b>click</b>", url: "javascript:alert(1)" }, { title: "ok", url: "https://example.com/a" }],
    };
    const h = await mount(view(apiOf(guidance({ ai: evil }))));
    expect(h.querySelector("img, script, iframe")).toBeNull();
    expect(h.textContent).toContain("<b>bold</b>"); // shown literally, not interpreted
    expect(h.textContent).toContain("<img src=x onerror=alert(1)> explanation");
    expect(h.textContent).toContain("+<script>alert(3)</script>");
    expect([...h.querySelectorAll("a")].map((a) => a.getAttribute("href"))).not.toContain("javascript:alert(1)");
    expect([...h.querySelectorAll(".ai a")].map((a) => a.getAttribute("href"))).toEqual(["https://example.com/a"]);
    expect(await axeIssues(h)).toEqual([]);
  });

  it("explains a rate limit, keeps the guidance, and lets you retry", async () => {
    const api = apiOf(guidance(), async () => { throw new ApiError(429, "AI suggestion limit reached (per minute); try again in 42s"); });
    const h = await mount(view(api));
    await clickButton(h, /Generate AI suggestion/);
    expect(h.querySelector("[role=alert]")?.textContent).toContain("try again in 42s");
    expect(h.textContent).toContain("Use prepared statements.");
    const btn = [...h.querySelectorAll("button")].find((b) => /Generate/.test(b.textContent ?? ""))!;
    expect(btn.disabled).toBe(false);
  });

  it("treats a rejected model answer as what it is: reference text plus the reason, not an AI suggestion", async () => {
    const degraded: Remediation = { ...STATIC, degraded_reason: "model reply rejected: patch must modify only the file the finding is in" };
    const h = await mount(view(apiOf(guidance(), async () => degraded)));
    await clickButton(h, /Generate AI suggestion/);
    expect(h.querySelector("[aria-label='AI suggestion']")).toBeNull();
    expect(h.textContent).toMatch(/model.s answer was not usable/);
    expect(h.textContent).toContain("patch must modify only the file");
  });

  it("reports load failures, and shows nothing from the previous finding when you move to another", async () => {
    const h = await mount(view(apiOf(new ApiError(503, "the remediation knowledge base is not loaded (run `bulwark kb load`)"))));
    expect(h.querySelector("[role=alert]")?.textContent).toContain("kb load");
    const withAi = apiOf(guidance({ ai: AI }));
    await act(async () => root!.render(view(withAi, "f1")));
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
    expect(document.body.textContent).toContain("Review before applying.");
    const next = apiOf(guidance({ finding_id: "f2" }));
    await act(async () => root!.render(view(next, "f2")));
    expect(document.body.textContent).not.toContain("Review before applying."); // reset immediately, not after the fetch
    expect(next.get).toHaveBeenCalledWith("s1", "f2");
  });

  it("copies the patch text", async () => {
    const writeText = vi.fn(async () => undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    const h = await mount(view(apiOf(guidance({ ai: AI }))));
    await clickButton(h, /Copy patch/);
    expect(writeText).toHaveBeenCalledWith(PATCH);
  });

  it("passes an accessibility audit in every state", async () => {
    for (const g of [guidance({ ai_enabled: false }), guidance(), guidance({ ai: AI })]) {
      const h = await mount(view(apiOf(g)));
      expect(await axeIssues(h)).toEqual([]);
    }
    const busy = await mount(view(apiOf(guidance()), "f1"));
    expect(await axeIssues(busy)).toEqual([]);
  });
});

describe("in the finding panel", () => {
  const scan = demo.scan as unknown as ScanView;
  const f = demo.findings[0] as unknown as Finding;
  it("appears only when a guidance source is provided", async () => {
    const without = await mount(<FindingDetail finding={f} scan={scan} onClose={() => undefined} />);
    expect(without.querySelector(".guidance")).toBeNull();
    const withApi = await mount(<FindingDetail finding={f} scan={scan} onClose={() => undefined} guidance={apiOf(guidance())} />);
    expect(withApi.querySelector(".guidance")).not.toBeNull();
  });

  it("the sample site's precomputed guidance is reference text only, for every sample finding", () => {
    const all = demoGuidance as unknown as Record<string, Remediation>;
    for (const finding of demo.findings as unknown as Finding[]) {
      const r = all[finding.id];
      expect(r, finding.id).toBeDefined();
      expect(r!.source).toBe("static");
      expect(r!.suggested_patch).toBeNull();
      expect(r!.label).toContain("not AI-generated");
    }
  });
});

describe("patch verification badge", () => {
  const withStatus = (status: Remediation["patch_status"]) => guidance({ ai: { ...AI, patch_status: status } });
  it("says when the patch was checked against the code, and never claims it is the right fix", async () => {
    const h = await mount(view(apiOf(withStatus("verified"))));
    expect(h.querySelector(".patch .tag.ok")?.textContent).toBe("Checked: matches the code");
    expect(h.querySelector(".patch")!.textContent).toContain("does not make it the right fix");
  });
  it("says when it could not be checked, and shows nothing when the status is unknown", async () => {
    const h = await mount(view(apiOf(withStatus("unverified"))));
    expect(h.querySelector(".patch .tag.warn-tag")?.textContent).toBe("Not fully checked");
    expect(h.querySelector(".patch")!.textContent).not.toContain("applies cleanly");
    const none = await mount(view(apiOf(withStatus(null))));
    expect(none.querySelector(".patch .tag")).toBeNull();
    expect(await axeIssues(none)).toEqual([]);
  });
});
