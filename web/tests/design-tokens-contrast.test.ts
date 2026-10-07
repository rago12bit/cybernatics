import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// Reads the real §29.2 tokens from design-system/tokens.css, so a color change that breaks AA
// fails CI — plan §29.2: "A CI script checks every text and background token pair against WCAG AA
// and fails the build on any regression." Same luminance/ratio math as tests/contrast.test.ts.
// The app has one theme, the site's dark blueprint, so there is one block to check.
const css = readFileSync(new URL("../design-system/tokens.css", import.meta.url), "utf8");

function block(source: string, selector: string): string {
  const start = source.indexOf(selector);
  if (start === -1) throw new Error(`selector not found: ${selector}`);
  const braceStart = source.indexOf("{", start);
  const braceEnd = source.indexOf("}", braceStart);
  return source.slice(braceStart, braceEnd);
}

const themeBlock = block(css, ":root {");

const token = (source: string, name: string) => new RegExp(`--ds-${name}:\\s*(#[0-9a-fA-F]{6})`).exec(source)?.[1] ?? "";

const lum = (hex: string) => {
  const [r, g, b] = [1, 3, 5]
    .map((i) => parseInt(hex.slice(i, i + 2), 16) / 255)
    .map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
};
const ratio = (a: string, b: string) => {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
  return (hi! + 0.05) / (lo! + 0.05);
};

const SURFACES = ["surface", "raised", "raised-2", "inset"];
const TEXT = ["ink", "ink-2", "muted", "brand", "ok", "danger", "sev-critical", "sev-high", "sev-medium", "sev-low", "sev-info"];

describe.each([["blueprint", themeBlock]])("WCAG AA contrast (4.5:1), %s theme", (_label, source) => {
  it("every token this test needs is present", () => {
    for (const n of [...SURFACES, ...TEXT]) expect(token(source, n), n).toMatch(/^#[0-9a-f]{6}$/i);
  });
  for (const t of TEXT) {
    it(`${t} is readable on every surface`, () => {
      for (const s of SURFACES) {
        expect(ratio(token(source, t), token(source, s)), `${t} on ${s}`).toBeGreaterThanOrEqual(4.5);
      }
    });
  }
});
