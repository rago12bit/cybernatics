// @vitest-environment jsdom
// Public pages: content below the fold rises into view as it is scrolled to; nothing on screen is hidden.
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ScrollReveal } from "../components/site/ScrollReveal";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let observed: Element[] = [];
let fire: (els: Element[]) => void = () => {};
class FakeIO {
  constructor(cb: (entries: { isIntersecting: boolean; target: Element }[]) => void) {
    fire = (els) => cb(els.map((target) => ({ isIntersecting: true, target })));
  }
  observe(el: Element) { observed.push(el); }
  unobserve(el: Element) { observed = observed.filter((x) => x !== el); }
  disconnect() { observed = []; }
}

const motion = (ok: boolean) => vi.stubGlobal("matchMedia", (q: string) => ({ matches: ok, media: q }));
let page: HTMLDivElement;
let root: Root;

function fact(top: number) {
  const el = document.createElement("div");
  el.className = "fact";
  el.getBoundingClientRect = () => ({ top, left: 0, bottom: top + 100, right: 100, width: 100, height: 100, x: 0, y: top, toJSON() {} });
  page.append(el);
  return el;
}

beforeEach(() => {
  observed = [];
  vi.stubGlobal("IntersectionObserver", FakeIO);
  vi.stubGlobal("innerHeight", 800);
  page = document.createElement("div");
  page.className = "page";
  document.body.append(page);
  root = createRoot(document.createElement("div"));
});
afterEach(async () => {
  await act(async () => root.unmount());
  page.remove();
  vi.unstubAllGlobals();
});

describe("scroll reveal on the public pages", () => {
  it("hides only what is below the fold, and brings it in one after another as it arrives", async () => {
    motion(true);
    const onScreen = fact(100);
    const below = [fact(900), fact(1300), fact(1700)];
    await act(async () => root.render(<ScrollReveal />));
    expect(onScreen.dataset.reveal).toBe("shown"); // never hidden, so no flash
    expect(below.map((e) => e.dataset.reveal)).toEqual(["armed", "armed", "armed"]);
    expect(observed).toEqual(below);

    fire([below[1]!, below[0]!]); // two arrive together, in any order
    expect(below[0]!.dataset.reveal).toBe("in");
    expect(below[1]!.dataset.reveal).toBe("in");
    expect(below[0]!.style.getPropertyValue("--reveal-delay")).toBe("0ms"); // top one first
    expect(below[1]!.style.getPropertyValue("--reveal-delay")).toBe("80ms");
    expect(below[2]!.dataset.reveal).toBe("armed");
    expect(observed).toEqual([below[2]]); // each arrives once
  });

  it("picks up content that renders later, such as a list that loads", async () => {
    motion(true);
    await act(async () => root.render(<ScrollReveal />));
    const late = fact(2000);
    await act(async () => { await new Promise((r) => setTimeout(r, 50)); });
    expect(late.dataset.reveal).toBe("armed");
  });

  it("leaves everything alone for anyone who asked for reduced motion, and cleans up after itself", async () => {
    motion(false);
    const below = fact(900);
    await act(async () => root.render(<ScrollReveal />));
    expect(below.dataset.reveal).toBeUndefined();

    motion(true);
    const root2 = createRoot(document.createElement("div"));
    await act(async () => root2.render(<ScrollReveal />));
    expect(below.dataset.reveal).toBe("armed");
    await act(async () => root2.unmount()); // leaving the page: nothing stays hidden
    expect(below.dataset.reveal).toBeUndefined();
  });
});
