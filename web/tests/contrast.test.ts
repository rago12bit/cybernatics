import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// Reads the real design tokens from globals.css, so a colour change that breaks AA fails CI.
const css = readFileSync(new URL("../app/globals.css", import.meta.url), "utf8");
const root = css.slice(css.indexOf(":root"), css.indexOf("}", css.indexOf(":root")));
const token = (name: string) => new RegExp(`--${name}:\\s*(#[0-9a-fA-F]{6})`).exec(root)?.[1] ?? "";

const lum = (hex: string) => {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
};
const ratio = (a: string, b: string) => {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
  return (hi! + 0.05) / (lo! + 0.05);
};

const SURFACES = ["bg", "panel", "panel-2", "inset"];
const TEXT = ["text", "text-2", "muted", "dim", "teal", "mint", "khaki", "sev-critical", "sev-high", "sev-medium", "sev-low", "sev-info"];

describe("WCAG AA contrast (4.5:1) for every text token on every surface", () => {
  it("tokens exist", () => {
    for (const n of [...SURFACES, ...TEXT]) expect(token(n), n).toMatch(/^#[0-9a-f]{6}$/i);
  });
  for (const t of TEXT) {
    it(`${t} is readable on all surfaces`, () => {
      for (const s of SURFACES) expect(ratio(token(t), token(s)), `${t} on ${s}`).toBeGreaterThanOrEqual(4.5);
    });
  }
  it("teal button text stays readable on its tinted background", () => {
    expect(ratio(token("teal"), "#0f2a25")).toBeGreaterThanOrEqual(4.5);
  });
});
