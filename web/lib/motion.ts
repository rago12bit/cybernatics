// Pure helpers for the landing-page motion (kept free of DOM access so they are unit-testable).

/** Motion is opt-out: everything here is skipped for users who ask the OS for reduced motion. */
export const MOTION_QUERY = "(prefers-reduced-motion: no-preference)";

export const clamp = (v: number, lo = 0, hi = 1): number => Math.min(hi, Math.max(lo, v));

/** Fast start, gentle landing: 0..1 in, 0..1 out. */
export const easeOutCubic = (t: number): number => 1 - Math.pow(1 - clamp(t), 3);

/** The number shown `t` (0..1) of the way through a count-up, rounded the way the final value is. */
export function countAt(target: number, t: number, decimals = 0): number {
  const factor = 10 ** decimals;
  return Math.round(target * easeOutCubic(t) * factor) / factor;
}

/** How far down the page the reader is, 0..1 (0 when the page does not scroll). */
export function scrollFraction(scrollY: number, scrollHeight: number, viewport: number): number {
  const room = scrollHeight - viewport;
  return room <= 0 ? 0 : clamp(scrollY / room);
}

/** Pointer position inside a box as percentages, for the spotlight's --mx / --my. */
export function pointerPercent(x: number, y: number, box: { left: number; top: number; width: number; height: number }) {
  return {
    mx: clamp((x - box.left) / (box.width || 1)) * 100,
    my: clamp((y - box.top) / (box.height || 1)) * 100,
  };
}
