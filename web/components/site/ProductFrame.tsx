"use client";

import { useId, useRef, useState, type KeyboardEvent } from "react";

/* The app itself, right under the headline: three real screens in a browser frame, captured from this
   build against the recorded OWASP Juice Shop scan (public/product/). Plain <img> with srcset rather
   than next/image, which writes an inline style the strict CSP would block. */

const SCREENS = [
  {
    id: "overview",
    tab: "Project overview",
    path: "app/projects/juice-shop",
    alt: "Bulwark's project overview for juice-shop/juice-shop: 10 issues put this project at real risk, a ranked Fix first list of SQL injections, what each scanner found, and the project's tabs.",
  },
  {
    id: "issue",
    tab: "An issue",
    path: "app/projects/juice-shop/issues",
    alt: "An issue in Bulwark: a sequelize SQL injection in Juice Shop, why it is ranked P2 at 73 out of 100, the line of code, and actions to mark it not a risk or request a risk acceptance.",
  },
  {
    id: "issues",
    tab: "Every issue",
    path: "app/issues?q=severity:high,critical",
    alt: "Bulwark's Issues list across projects, filtered with the query project:*juice-shop* severity:high,critical to 12 issues, with saved views and filters beside it.",
  },
] as const;

export function ProductFrame() {
  const uid = useId();
  const [active, setActive] = useState(0);
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  const s = SCREENS[active]!;

  const select = (i: number) => { setActive(i); tabs.current[i]?.focus(); };
  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const last = SCREENS.length - 1;
    const next = { ArrowRight: active === last ? 0 : active + 1, ArrowLeft: active === 0 ? last : active - 1, Home: 0, End: last }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    select(next);
  };

  return (
    <figure className="pframe">
      <div className="pframe-bar">
        <span className="dots" aria-hidden="true"><i /><i /><i /></span>
        <span className="pframe-url" aria-hidden="true">bulwark / {s.path}</span>
        <div className="pframe-tabs" role="tablist" aria-label="Screens of the app" onKeyDown={onKey}>
          {SCREENS.map((x, i) => (
            <button
              key={x.id}
              ref={(el) => { tabs.current[i] = el; }}
              type="button"
              role="tab"
              id={`${uid}-${x.id}`}
              aria-selected={i === active}
              aria-controls={`${uid}-shot`}
              tabIndex={i === active ? 0 : -1}
              onClick={() => select(i)}
            >
              {x.tab}
            </button>
          ))}
        </div>
      </div>
      <div className="pframe-shot" role="tabpanel" id={`${uid}-shot`} aria-labelledby={`${uid}-${s.id}`}>
        {/* Every screen is in the DOM, so switching is instant and the browser can fetch them early;
            only the first loads before the page is idle. */}
        {SCREENS.map((x, i) => (
          <img
            key={x.id}
            src={`/product/${x.id}-1200.webp`}
            srcSet={`/product/${x.id}-1200.webp 1200w, /product/${x.id}-2400.webp 2400w`}
            sizes="(min-width: 1280px) 1200px, 100vw"
            width={1200}
            height={750}
            alt={i === active ? x.alt : ""}
            aria-hidden={i === active ? undefined : true}
            className={i === active ? "on" : undefined}
            loading={i === 0 ? "eager" : "lazy"}
            decoding="async"
            fetchPriority={i === 0 ? "high" : "low"}
          />
        ))}
      </div>
    </figure>
  );
}
