"use client";

import { Fragment, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { MOTION_QUERY, countAt, pointerPercent, scrollFraction } from "@/lib/motion";

// Layout effect on the client (no flash of the final value), plain effect on the server (no warning).
const useIsoLayoutEffect = typeof window === "undefined" ? useEffect : useLayoutEffect;

const motionOk = () => typeof window !== "undefined" && window.matchMedia?.(MOTION_QUERY).matches === true;

/**
 * A number that counts up the first time it scrolls into view. The server (and no-JS, and reduced-motion)
 * output is the final value, so nothing depends on the animation running. Screen readers always get the
 * final value: before, a number still waiting below the fold read as "0".
 */
export function CountUp({ value, decimals = 0, suffix = "", ms = 1300, group = false }: { value: number; decimals?: number; suffix?: string; ms?: number; group?: boolean }) {
  // `group` writes 2,552 rather than 2552, as the rest of the page writes large numbers.
  const fmt = (n: number) => (group ? n.toLocaleString("en-US", { minimumFractionDigits: decimals, maximumFractionDigits: decimals }) : n.toFixed(decimals));
  const ref = useRef<HTMLSpanElement>(null);
  const [shown, setShown] = useState(value);

  useIsoLayoutEffect(() => {
    const el = ref.current;
    if (!el || !motionOk() || typeof IntersectionObserver === "undefined") return;
    setShown(0);
    let raf = 0;
    const io = new IntersectionObserver((entries) => {
      if (!entries.some((e) => e.isIntersecting)) return;
      io.disconnect();
      const t0 = performance.now();
      const tick = (now: number) => {
        const t = (now - t0) / ms;
        setShown(countAt(value, t, decimals));
        if (t < 1) raf = requestAnimationFrame(tick);
      };
      raf = requestAnimationFrame(tick);
    }, { threshold: 0.4 });
    io.observe(el);
    return () => { io.disconnect(); cancelAnimationFrame(raf); };
  }, [value, decimals, ms]);

  // Assistive tech and copy-paste get the real value at once; only the eye sees it count.
  return (
    <span ref={ref}>
      <span className="sr-only">{fmt(value)}{suffix}</span>
      <span aria-hidden="true">{fmt(shown)}{suffix}</span>
    </span>
  );
}

/**
 * Fades and lifts its content in when it first scrolls into view. Anything already on screen at load is
 * left alone (no hide-then-show flash), and it stays visible without JS or under reduced motion.
 */
export function Reveal({ children, className = "", delay = 0, glow = false }: { children: ReactNode; className?: string; delay?: 0 | 1 | 2 | 3 | 4 | 5; glow?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<"visible" | "armed" | "in">("visible");

  useIsoLayoutEffect(() => {
    const el = ref.current;
    if (!el || !motionOk() || typeof IntersectionObserver === "undefined") return;
    const r = el.getBoundingClientRect();
    if (r.top < window.innerHeight && r.bottom > 0) return; // already visible at load
    setState("armed");
    const io = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) { setState("in"); io.disconnect(); }
    }, { threshold: 0.12 });
    io.observe(el);
    return () => io.disconnect();
  }, []);

  const cls = `${className} ${state === "visible" ? "" : "reveal"} ${state === "in" ? "in" : ""} ${delay ? `rd${delay}` : ""} ${glow ? "glow-box" : ""}`.trim().replace(/\s+/g, " ");
  return <div ref={ref} className={cls} onPointerMove={glow ? trackPointer : undefined}>{children}</div>;
}

function trackPointer(e: React.PointerEvent<HTMLElement>) {
  if (e.pointerType !== "mouse" || !motionOk()) return;
  const el = e.currentTarget;
  const { mx, my } = pointerPercent(e.clientX, e.clientY, el.getBoundingClientRect());
  el.style.setProperty("--mx", `${mx.toFixed(1)}%`);
  el.style.setProperty("--my", `${my.toFixed(1)}%`);
}

/** A soft light that follows the pointer inside the box (the position goes into --mx / --my via the CSSOM). */
export function Glow({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`glow-box ${className}`.trim()} onPointerMove={trackPointer}>{children}</div>;
}

/** A hairline under the header that fills as the page is read. Decorative, so hidden from assistive tech. */
export function ScrollProgress() {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el || !motionOk()) return;
    let raf = 0;
    const update = () => {
      raf = 0;
      const f = scrollFraction(window.scrollY, document.documentElement.scrollHeight, window.innerHeight);
      el.style.setProperty("--p", f.toFixed(4));
    };
    const onScroll = () => { if (!raf) raf = requestAnimationFrame(update); };
    update();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
    return () => { window.removeEventListener("scroll", onScroll); window.removeEventListener("resize", onScroll); cancelAnimationFrame(raf); };
  }, []);
  return <div ref={ref} className="scroll-progress" aria-hidden="true" />;
}

/** Splits text into words that rise from behind a mask. Pure CSS animation (see .rise), so it needs no JS and no flash. */
export function RiseText({ text }: { text: string }) {
  return (
    <span className="rise">
      {text.split(" ").map((w, i) => (
        <Fragment key={i}>
          {i > 0 && " "}
          <span><span className="rv"><span>{w}</span></span></span>
        </Fragment>
      ))}
    </span>
  );
}
