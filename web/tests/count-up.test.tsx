// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CountUp } from "../components/site/Motion";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root | null = null;
afterEach(() => { act(() => root?.unmount()); root = null; vi.unstubAllGlobals(); });

describe("CountUp, before it scrolls into view", () => {
  it("still gives screen readers the real number, not the 0 it animates from", async () => {
    // Motion allowed, and an observer that never fires: the number is below the fold.
    vi.stubGlobal("matchMedia", (q: string) => ({ matches: q.includes("no-preference"), media: q, addEventListener() {}, removeEventListener() {} }));
    vi.stubGlobal("IntersectionObserver", class { observe() {} disconnect() {} });
    const host = document.createElement("div");
    document.body.replaceChildren(host);
    root = createRoot(host);
    await act(async () => root!.render(<h2><CountUp value={28.5} decimals={1} suffix="%" /></h2>));

    const shown = host.querySelector("[aria-hidden=true]")!;
    expect(shown.textContent).toBe("0.0%"); // what the eye sees, waiting to count
    const read = [...host.querySelectorAll("h2 *")].filter((e) => !e.closest("[aria-hidden=true]") && e.children.length === 0);
    expect(read.map((e) => e.textContent).join("")).toBe("28.5%");
  });
});
