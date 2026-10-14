// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const made: { options: Record<string, unknown>; destroyed: boolean }[] = [];
vi.mock("lenis", () => ({
  default: class {
    rec: { options: Record<string, unknown>; destroyed: boolean };
    constructor(options: Record<string, unknown>) {
      this.rec = { options, destroyed: false };
      made.push(this.rec);
    }
    destroy() {
      this.rec.destroyed = true;
    }
  },
}));
vi.mock("lenis/dist/lenis.css", () => ({}));

import { SmoothScroll } from "../components/site/SmoothScroll";

let host: HTMLDivElement;
let root: Root;

const motion = (ok: boolean) =>
  vi.stubGlobal("matchMedia", (q: string) => ({ matches: ok, media: q, addEventListener() {}, removeEventListener() {} }));

beforeEach(() => {
  made.length = 0;
  document.documentElement.style.setProperty("--header-h", "3.5rem");
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});
afterEach(() => {
  vi.unstubAllGlobals();
  host.remove();
});

describe("smooth scrolling on the public site", () => {
  it("eases wheel scrolling, lands anchors below the header, and stops when the page goes", async () => {
    motion(true);
    await act(async () => root.render(<SmoothScroll />));
    expect(made).toHaveLength(1);
    const [lenis] = made;
    expect(lenis?.options).toMatchObject({ autoRaf: true, lerp: 0.1, anchors: { offset: -56 } });
    await act(async () => root.unmount()); // leaving for /app: native scrolling again
    expect(lenis?.destroyed).toBe(true);
  });

  it("is off for anyone who asked for reduced motion", async () => {
    motion(false);
    await act(async () => root.render(<SmoothScroll />));
    expect(made).toHaveLength(0);
    await act(async () => root.unmount());
  });
});
