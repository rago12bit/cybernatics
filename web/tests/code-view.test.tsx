// @vitest-environment jsdom
/* CodeView under the production CSP (proxy.ts): no WebAssembly (script-src has no 'wasm-unsafe-eval')
 * and no HTML with style attributes (style-src has no 'unsafe-inline'). Before, Shiki's default
 * engine compiled WebAssembly, the browser refused, and every snippet in production was plain text;
 * its HTML output's colours would have been dropped too. */
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { CodeView } from "../design-system/code-view";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

afterEach(() => {
  document.body.innerHTML = "";
  vi.restoreAllMocks();
});

async function render(code: string, path: string, highlightLine?: number): Promise<HTMLElement> {
  const host = document.createElement("div");
  document.body.append(host);
  await act(async () => createRoot(host).render(<CodeView code={code} path={path} highlightLine={highlightLine} />));
  await vi.waitFor(() => expect(host.querySelector(".ds-code-shiki")).not.toBeNull(), { timeout: 15_000 });
  return host;
}

it("highlights without WebAssembly, colouring tokens and marking the flagged line", async () => {
  const instantiate = vi.spyOn(WebAssembly, "instantiate");
  const compile = vi.spyOn(WebAssembly, "compile");
  const host = await render('import os\nos.system("ls " + user)\n', "app/run.py", 2);

  expect(instantiate).not.toHaveBeenCalled();
  expect(compile).not.toHaveBeenCalled();
  const lines = host.querySelectorAll(".line");
  expect(lines).toHaveLength(3);
  expect(lines[1]!.classList.contains("ds-code-highlight")).toBe(true);
  expect(lines[0]!.classList.contains("ds-code-highlight")).toBe(false);
  const colours = new Set([...host.querySelectorAll<HTMLElement>(".line span")].map((s) => s.style.color));
  expect(colours.size).toBeGreaterThan(1); // more than one colour: it really tokenized Python
  expect(host.textContent).toBe('import os\nos.system("ls " + user)\n');
}, 20_000);

it("renders hostile source as text, never as markup", async () => {
  const host = await render('<img src=x onerror="alert(1)"><script>alert(2)</script>\n', "page.html");
  expect(host.querySelector("img, script")).toBeNull();
  expect(host.textContent).toContain('<img src=x onerror="alert(1)">');
}, 20_000);

it("shows a file with no known language as plain text", async () => {
  const host = document.createElement("div");
  document.body.append(host);
  await act(async () => createRoot(host).render(<CodeView code="hello" path="NOTES" />));
  expect(host.querySelector("pre.ds-code-plain")?.textContent).toBe("hello");
});
