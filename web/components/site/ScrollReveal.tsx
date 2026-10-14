"use client";

import { useEffect } from "react";
import { MOTION_QUERY } from "@/lib/motion";

/** What rises into view on the public pages: section headings, fact cells, table rows, steps, cards. */
export const REVEAL_SELECTOR = [
  ".site-sec > .sec-head",
  ".site-body > *",
  ".fact",
  ".cmp thead tr",
  ".cmp tbody tr",
  ".steps > li",
  ".cat-group > h2",
  ".cards > li",
  ".reveal-me",
].join(", ");

const STEP_MS = 80; // between elements that come into view together
const MAX_MS = 400;

/**
 * Elements below the fold fade and rise into place as they scroll into view, one after another
 * when several arrive together. Whatever is on screen when it appears is left alone (no
 * hide-then-show flash), nothing is hidden without JS or under reduced motion, and an element
 * arrives once. Content rendered later (a list that loads, a filter) is picked up as it appears.
 * State lives in a data attribute rather than the class, so React re-renders never undo it.
 */
export function ScrollReveal({ selector = REVEAL_SELECTOR }: { selector?: string }) {
  useEffect(() => {
    if (window.matchMedia?.(MOTION_QUERY).matches !== true || typeof IntersectionObserver === "undefined") return;
    const seen: HTMLElement[] = [];
    const top = (el: Element) => el.getBoundingClientRect();
    const io = new IntersectionObserver(
      (entries) => {
        const arriving = entries
          .filter((e) => e.isIntersecting)
          .map((e) => e.target as HTMLElement)
          .sort((a, b) => top(a).top - top(b).top || top(a).left - top(b).left);
        arriving.forEach((el, i) => {
          io.unobserve(el);
          el.style.setProperty("--reveal-delay", `${Math.min(i * STEP_MS, MAX_MS)}ms`);
          el.dataset.reveal = "in";
        });
      },
      { rootMargin: "0px 0px -6% 0px" },
    );
    const arm = () => {
      for (const el of document.querySelectorAll<HTMLElement>(selector)) {
        if (el.dataset.reveal) continue;
        seen.push(el);
        if (top(el).top < window.innerHeight) { el.dataset.reveal = "shown"; continue; } // already in view
        el.dataset.reveal = "armed";
        io.observe(el);
      }
    };
    arm();
    let queued = 0;
    const mo = new MutationObserver(() => { if (!queued) queued = requestAnimationFrame(() => { queued = 0; arm(); }); });
    mo.observe(document.querySelector(".page") ?? document.body, { childList: true, subtree: true });
    return () => {
      mo.disconnect();
      io.disconnect();
      cancelAnimationFrame(queued);
      for (const el of seen) { delete el.dataset.reveal; el.style.removeProperty("--reveal-delay"); }
    };
  }, [selector]);
  return null;
}
