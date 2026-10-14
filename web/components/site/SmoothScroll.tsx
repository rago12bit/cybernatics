"use client";

import { useEffect } from "react";
import Lenis from "lenis";
import "lenis/dist/lenis.css";
import { MOTION_QUERY } from "@/lib/motion";

/**
 * Inertial wheel scrolling for the public site (the home page and the site pages), not the app.
 *
 * Lenis eases the page's own scroll position rather than moving the page inside a transformed
 * wrapper, so `position: sticky` keeps working (the home page's section stack pins with it), and
 * scroll events, IntersectionObserver and anchors behave as they do natively. Touch keeps the
 * device's own scrolling, and anyone who asked for reduced motion gets plain scrolling. Mounted by
 * each public page, so it is gone again in /app, whose tables and side sheets scroll natively.
 */
export function SmoothScroll() {
  useEffect(() => {
    if (!window.matchMedia(MOTION_QUERY).matches) return;
    const header = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--header-h"));
    const rem = parseFloat(getComputedStyle(document.documentElement).fontSize) || 16;
    const lenis = new Lenis({
      autoRaf: true,
      lerp: 0.1, // about half a second to settle, close to antigravity.google's 0.6 s
      anchors: { offset: -(header * rem || 56) }, // in-page links land below the sticky header
    });
    return () => lenis.destroy();
  }, []);
  return null;
}
