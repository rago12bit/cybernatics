import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { CountUp, Reveal, RiseText, ScrollProgress } from "../components/site/Motion";
import { clamp, countAt, easeOutCubic, pointerPercent, scrollFraction } from "../lib/motion";

describe("motion helpers", () => {
  it("eases from 0 to 1 and clamps outside the range", () => {
    expect(easeOutCubic(0)).toBe(0);
    expect(easeOutCubic(1)).toBe(1);
    expect(easeOutCubic(-3)).toBe(0);
    expect(easeOutCubic(9)).toBe(1);
    expect(easeOutCubic(0.5)).toBeGreaterThan(0.5); // fast start
    expect(clamp(5, 0, 2)).toBe(2);
  });

  it("counts up to exactly the target, rounded like the final value", () => {
    expect(countAt(8.9, 1, 1)).toBe(8.9);
    expect(countAt(8.9, 0, 1)).toBe(0);
    expect(countAt(5, 0.5)).toBeLessThanOrEqual(5);
    expect(Number.isInteger(countAt(5, 0.3))).toBe(true);
  });

  it("reports scroll progress, and 0 for a page that does not scroll", () => {
    expect(scrollFraction(0, 2000, 1000)).toBe(0);
    expect(scrollFraction(500, 2000, 1000)).toBe(0.5);
    expect(scrollFraction(5000, 2000, 1000)).toBe(1);
    expect(scrollFraction(0, 800, 1000)).toBe(0);
  });

  it("maps the pointer to percentages inside the box", () => {
    const box = { left: 100, top: 50, width: 200, height: 100 };
    expect(pointerPercent(200, 100, box)).toEqual({ mx: 50, my: 50 });
    expect(pointerPercent(0, 0, box)).toEqual({ mx: 0, my: 0 });
    expect(pointerPercent(999, 999, box)).toEqual({ mx: 100, my: 100 });
  });
});

describe("motion components render safely on the server", () => {
  it("shows the final number, so no-JS and reduced motion see the real value", () => {
    expect(renderToStaticMarkup(<CountUp value={8.9} decimals={1} suffix="%" />)).toContain("8.9%");
    expect(renderToStaticMarkup(<CountUp value={5} />)).toContain(">5<");
  });

  it("keeps revealed content visible until JS decides to hide it", () => {
    const html = renderToStaticMarkup(<Reveal className="fcell" delay={2} glow>hello</Reveal>);
    expect(html).toContain("hello");
    expect(html).not.toContain("reveal"); // never server-hidden
    expect(html).toContain("glow-box");
  });

  it("keeps the headline readable as plain text, with no inline styles", () => {
    const html = renderToStaticMarkup(<h1><RiseText text="Security scanning, without the noise." /></h1>);
    expect(html.replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim()).toBe("Security scanning, without the noise.");
    expect(html).not.toMatch(/\sstyle=/);
  });

  it("marks the progress bar decorative", () => {
    expect(renderToStaticMarkup(<ScrollProgress />)).toContain('aria-hidden="true"');
  });
});
