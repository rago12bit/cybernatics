// Pure geometry for the sticky "slide over" section stack (kept free of DOM access so it is unit-testable).

/**
 * Where a section should pin (its CSS `top`, in px).
 * A section that fits under the header pins right below it. A taller one pins at `viewport - height`
 * (negative), so its *bottom* meets the viewport bottom: the reader always scrolls through all of it
 * before the next section starts to cover it.
 */
export function stackTop(height: number, viewport: number, header: number): number {
  return height + header <= viewport ? header : viewport - height;
}

/**
 * How far this section has been covered by the one sliding over it, 0..1.
 * `bottom` is this section's visible bottom edge, `nextTop` the next section's top edge, both in
 * viewport coordinates. Covering starts when the next section's top rises above this one's bottom
 * (which only happens once this section is pinned) and completes when it has covered the visible span.
 */
export function coverProgress(bottom: number, nextTop: number, visibleSpan: number): number {
  if (visibleSpan <= 0) return 0;
  const covered = bottom - nextTop;
  return Math.min(1, Math.max(0, covered / visibleSpan));
}

/** Stacking is only for wide screens and users who have not asked for reduced motion. */
export const STACK_QUERY = "(min-width: 961px) and (prefers-reduced-motion: no-preference)";
