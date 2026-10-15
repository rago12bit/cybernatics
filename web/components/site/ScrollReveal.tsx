"use client";

import { useEffect } from "react";
import { MOTION_QUERY } from "@/lib/motion";
import { REVEAL_SELECTOR } from "@/lib/reveal";

const STEP_MS = 80; // between elements that come into view together
const MAX_MS = 400;
const SETTLE_MS = 1200; // the longest transition (globals.css), then the element is left alone

/**
 * Elements below the fold fade and rise into place as they scroll into view, one after another
 * when several arrive together. Whatever is on screen when it appears is left alone (no
 * hide-then-show flash), nothing is hidden without JS or under reduced motion, and an element
 * arrives once. Content rendered later (a list that loads, a filter, the next page in the app) is
 * picked up as it appears.
 * State lives in a data attribute rather than the class, so React re-renders never undo it.
 */
export function ScrollReveal({ selector = REVEAL_SELECTOR }: { selector?: string }) {
  useEffect(() => {
    if (window.matchMedia?.(MOTION_QUERY).matches !== true || typeof IntersectionObserver === "undefined") return;
    const seen = new Set<HTMLElement>();
    const timers = new Set<number>();
    const top = (el: Element) => el.getBoundingClientRect();
    const io = new IntersectionObserver(
      (entries) => {
        const arriving = entries
          .filter((e) => e.isIntersecting)
          .map((e) => e.target as HTMLElement)
          .sort((a, b) => top(a).top - top(b).top || top(a).left - top(b).left);
        arriving.forEach((el, i) => {
          io.unobserve(el);
          const delay = Math.min(i * STEP_MS, MAX_MS);
          el.style.setProperty("--reveal-delay", `${delay}ms`);
          el.dataset.reveal = "in";
          // Once it has arrived, hand the element back to its own styles (its own transitions, and
          // no transform that would trap a position:fixed descendant such as a side sheet).
          const t = window.setTimeout(() => { timers.delete(t); if (el.dataset.reveal === "in") el.dataset.reveal = "done"; }, delay + SETTLE_MS);
          timers.add(t);
        });
      },
      // No negative margin: a block at the very end of a page must still be able to arrive.
      { rootMargin: "0px" },
    );
    const arm = () => {
      for (const el of seen) if (!el.isConnected) seen.delete(el); // pages come and go in the app
      for (const el of document.querySelectorAll<HTMLElement>(selector)) {
        if (el.dataset.reveal) continue;
        seen.add(el);
        // Inside something that is itself rising in: it moves with its parent, not twice.
        const parent = el.parentElement?.closest<HTMLElement>("[data-reveal]");
        if (parent && (parent.dataset.reveal === "armed" || parent.dataset.reveal === "in")) { el.dataset.reveal = "shown"; continue; }
        if (top(el).top < window.innerHeight) { el.dataset.reveal = "shown"; continue; } // already in view
        el.dataset.reveal = "armed";
        io.observe(el);
      }
    };
    arm();
    let queued = 0;
    const mo = new MutationObserver(() => { if (!queued) queued = requestAnimationFrame(() => { queued = 0; arm(); }); });
    mo.observe(document.body, { childList: true, subtree: true });
    return () => {
      mo.disconnect();
      io.disconnect();
      cancelAnimationFrame(queued);
      for (const t of timers) clearTimeout(t);
      for (const el of seen) { delete el.dataset.reveal; el.style.removeProperty("--reveal-delay"); }
    };
  }, [selector]);
  return null;
}
