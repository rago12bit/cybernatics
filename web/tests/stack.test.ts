import { describe, expect, it } from "vitest";
import { coverProgress, stackTop } from "../lib/stack";

describe("stackTop: where a section pins", () => {
  it("a section that fits pins just under the header", () => {
    expect(stackTop(500, 800, 56)).toBe(56);
    expect(stackTop(744, 800, 56)).toBe(56); // fits exactly
  });
  it("a section taller than the viewport pins by its bottom edge (negative top)", () => {
    expect(stackTop(1200, 800, 56)).toBe(-400); // its last 800px stay visible while pinned
    expect(stackTop(745, 800, 56)).toBe(55); // 1px too tall: just barely negative-shifted
  });
  it("never hides content: a tall section pins with its bottom on the viewport bottom", () => {
    for (const h of [745, 900, 2400]) expect(stackTop(h, 800, 56) + h).toBe(800);
    for (const h of [300, 744]) {
      const top = stackTop(h, 800, 56);
      expect(top).toBe(56); // fits: sits under the header
      expect(top + h).toBeLessThanOrEqual(800); // and is fully visible
    }
  });
});

describe("coverProgress: how much the next section has covered this one", () => {
  it("is 0 until the next section rises above this one's bottom edge", () => {
    expect(coverProgress(700, 900, 600)).toBe(0); // next is below: no cover
    expect(coverProgress(700, 700, 600)).toBe(0); // touching: not yet covering
  });
  it("grows linearly as the next section slides up, and clamps at 1", () => {
    expect(coverProgress(700, 400, 600)).toBeCloseTo(0.5);
    expect(coverProgress(700, 100, 600)).toBe(1);
    expect(coverProgress(700, -500, 600)).toBe(1);
  });
  it("is safe with a zero or negative span", () => {
    expect(coverProgress(700, 300, 0)).toBe(0);
    expect(coverProgress(700, 300, -5)).toBe(0);
  });
});
