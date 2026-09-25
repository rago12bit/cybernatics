// The hand-scoring page for the fix-quality evaluation (benchmarks/remediation/scorer_template.html), run in a
// simulated browser. It is a standalone offline file, so this is the only place it is exercised.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { JSDOM } = require("jsdom") as { JSDOM: new (html: string, opts: Record<string, unknown>) => { window: any } };

const TEMPLATE = readFileSync(new URL("../../benchmarks/remediation/scorer_template.html", import.meta.url), "utf8");
const finding = (title: string, snippet = "eval(x)") => ({
  title, description: "d", location: { path: "a.py", start_line: 3, end_line: 3, snippet },
  taxonomy: { category: "sast", cwe: ["CWE-95"] },
});
const item = (id: string, over: Record<string, unknown> = {}, patch: string | null = null, source = "ai") => ({
  item_id: id, repo: "https://github.com/x/y", rule: "semgrep/r", finding: finding(`finding ${id}`),
  result: { source, explanation: "expl " + id, impact: "impact", fix_summary: "fix " + id, suggested_patch: patch, ...over },
});

// Same embedding rule as run.py: '<' and '&' are escaped so the JSON cannot close the script tag.
function page(items: unknown[]) {
  const data = JSON.stringify({ run: "t1", items, static: Object.fromEntries((items as { item_id: string }[]).map((i) => [i.item_id, { explanation: "ref " + i.item_id, fix_summary: "ref fix" }])) })
    .replace(/</g, "\\u003c").replace(/&/g, "\\u0026");
  const dom = new JSDOM(TEMPLATE.replace("__DATA__", data), { runScripts: "dangerously", url: "https://scoring.test/" });
  const w = dom.window;
  const blobs: string[] = [];
  w.URL.createObjectURL = (b: Blob) => { void b.text().then((t: string) => blobs.push(t)); return "blob:x"; };
  w.HTMLAnchorElement.prototype.click = () => undefined;
  return { w, d: w.document as Document, blobs };
}
const pick = (d: Document, name: string, value: number) => {
  const r = [...d.querySelectorAll<HTMLInputElement>(`input[type=radio][name^="${name}-"]`)].find((x) => x.value === String(value))!;
  r.checked = true;
  r.dispatchEvent(new (d.defaultView as any).Event("change", { bubbles: true }));
};
const scoreAll = (d: Document, fix = 2) => { pick(d, "explanation_accurate", 2); pick(d, "fix_correct", fix); pick(d, "unsafe", 0); pick(d, "hallucination", 0); };
const next = (d: Document) => (d.getElementById("next") as HTMLButtonElement).click();

describe("scoring page", () => {
  it("shows the finding, the code and the model's answer, and counts progress", () => {
    const { d } = page([item("a"), item("b")]);
    expect(d.getElementById("progress")!.textContent).toBe("0 of 2 scored");
    expect(d.getElementById("item")!.textContent).toContain("finding a");
    expect(d.querySelector("pre")!.textContent).toBe("eval(x)");
    expect(d.getElementById("item")!.textContent).toContain("expl a");
    expect(d.getElementById("item")!.textContent).toContain("ref a"); // the non-AI baseline is shown for comparison
    scoreAll(d);
    expect(d.getElementById("progress")!.textContent).toBe("1 of 2 scored");
  });

  it("renders hostile finding and model text as text, never as HTML", () => {
    const evil = "<img src=x onerror=alert(1)><script>window.pwned=1</script>";
    const { d, w } = page([item("a", { explanation: evil, fix_summary: evil }, "--- a/x\n+++ b/x\n" + evil)]);
    expect(d.querySelector("#item img, #item script")).toBeNull();
    expect(d.getElementById("item")!.textContent).toContain(evil);
    expect(w.pwned).toBeUndefined();
  });

  it("does not let the embedded data break out of its script tag", () => {
    const { d, w } = page([item("a", { explanation: "</script><script>window.pwned=1</script>" })]);
    expect(w.pwned).toBeUndefined();
    expect(d.getElementById("item")!.textContent).toContain("</script><script>window.pwned=1</script>");
  });

  it("asks about the patch only when there is one", () => {
    const a = page([item("a")]).d;
    expect(a.querySelector('input[name^="patch_correct-"]')).toBeNull();
    const b = page([item("b", {}, "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n")]).d;
    expect(b.querySelector('input[name^="patch_correct-"]')).not.toBeNull();
    expect(b.querySelectorAll("pre").length).toBe(2); // the code and the patch
  });

  it("tells the scorer when the model's answer was not usable", () => {
    const { d } = page([item("a", {}, null, "static")]);
    expect(d.getElementById("item")!.textContent).toMatch(/answer was not usable/);
  });

  it("is blind: it does not render the model's confidence, the automatic patch check, or warnings", () => {
    const { d } = page([item("a", { confidence: "high", patch_status: "verified", warnings: ["secret warning"] })]);
    const shown = d.getElementById("item")!.textContent!; // what a person sees (the data block is not visible)
    expect(shown).not.toMatch(/patch_status|verified|secret warning|confidence: /i);
  });

  it("navigates, remembers scores across a reload, and disables prev/next at the ends", () => {
    const one = page([item("a"), item("b")]);
    const { d, w } = one;
    expect((d.getElementById("prev") as HTMLButtonElement).disabled).toBe(true);
    scoreAll(d, 1);
    next(d);
    expect(d.getElementById("item")!.textContent).toContain("finding b");
    expect((d.getElementById("next") as HTMLButtonElement).disabled).toBe(true);
    const saved = w.localStorage.getItem("bulwark-scoring-t1");
    expect(JSON.parse(saved).a.fix_correct).toBe(1);
    // a second load of the same page (same origin storage) restores it
    const dom2 = new JSDOM(TEMPLATE.replace("__DATA__", JSON.stringify({ run: "t1", items: [item("a"), item("b")], static: { a: { explanation: "r", fix_summary: "r" }, b: { explanation: "r", fix_summary: "r" } } })), { runScripts: "dangerously", url: "https://scoring.test/" });
    dom2.window.localStorage.setItem("bulwark-scoring-t1", saved);
    expect(saved).toContain('"fix_correct":1');
  });

  it("exports exactly what was scored, and says when items are still missing", async () => {
    const { d, blobs } = page([item("a"), item("b")]);
    scoreAll(d, 2);
    (d.getElementById("export") as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 20));
    const out = JSON.parse(blobs[0]!);
    expect(Object.keys(out)).toEqual(["a"]);
    expect(out.a).toMatchObject({ explanation_accurate: 2, fix_correct: 2, unsafe: 0, hallucination: 0 });
    expect(d.getElementById("msg")!.textContent).toMatch(/1 item\(s\) are not fully scored/);
    next(d);
    scoreAll(d, 0);
    (d.getElementById("export") as HTMLButtonElement).click();
    expect(d.getElementById("msg")!.textContent).toMatch(/all items scored/);
    await new Promise((r) => setTimeout(r, 20));
    expect(Object.keys(JSON.parse(blobs[1]!)).sort()).toEqual(["a", "b"]);
  });

  it("stores notes with the scores", () => {
    const { d, w } = page([item("a")]);
    const ta = d.querySelector("textarea")!;
    ta.value = "the fix uses an API that does not exist";
    ta.dispatchEvent(new w.Event("input", { bubbles: true }));
    expect(JSON.parse(w.localStorage.getItem("bulwark-scoring-t1")!).a.notes).toContain("does not exist");
  });
});
