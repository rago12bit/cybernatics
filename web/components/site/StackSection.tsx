"use client";

import { useEffect, useRef, type ReactNode } from "react";
import { coverProgress, stackTop, STACK_QUERY } from "@/lib/stack";

/**
 * A landing-page section that pins while the next one slides up over it (the reference recording's
 * scroll effect). Geometry is measured in JS and applied through the CSSOM (`element.style.*`), which
 * the strict CSP permits, unlike inline `style=""` attributes. As it gets covered it dims and scales
 * down slightly via the --cover custom property (transform/opacity only). Disabled entirely under
 * reduced motion and on narrow screens, where sections simply flow.
 */
export function StackSection({ children, index, className = "" }: { children: ReactNode; index: number; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const mq = window.matchMedia(STACK_QUERY);
    let raf = 0;
    let top = 0;

    const layout = () => {
      if (!mq.matches) {
        el.classList.remove("stacked");
        el.style.removeProperty("top");
        el.style.removeProperty("z-index");
        el.style.setProperty("--cover", "0");
        return;
      }
      const header = document.querySelector<HTMLElement>(".top")?.offsetHeight ?? 0;
      top = stackTop(el.offsetHeight, window.innerHeight, header);
      el.classList.add("stacked");
      el.style.top = `${top}px`;
      el.style.zIndex = String(index + 1); // later sections slide over earlier ones
      update();
    };

    const update = () => {
      raf = 0;
      if (!mq.matches) return;
      const next = el.nextElementSibling as HTMLElement | null;
      if (!next) return void el.style.setProperty("--cover", "0");
      const r = el.getBoundingClientRect();
      const header = document.querySelector<HTMLElement>(".top")?.offsetHeight ?? 0;
      const span = Math.min(r.height, window.innerHeight - header);
      const p = coverProgress(r.bottom, next.getBoundingClientRect().top, span);
      el.style.setProperty("--cover", p.toFixed(3));
    };
    const onScroll = () => { if (!raf) raf = requestAnimationFrame(update); };

    layout();
    const ro = new ResizeObserver(layout); // content height changes (fonts, accordion) re-pin correctly
    ro.observe(el);
    window.addEventListener("resize", layout);
    window.addEventListener("scroll", onScroll, { passive: true });
    mq.addEventListener("change", layout);
    return () => {
      ro.disconnect();
      window.removeEventListener("resize", layout);
      window.removeEventListener("scroll", onScroll);
      mq.removeEventListener("change", layout);
      if (raf) cancelAnimationFrame(raf);
    };
  }, [index]);

  return (
    <div ref={ref} className={`stack-sec ${className}`}>
      <div className="stack-inner">{children}</div>
    </div>
  );
}
