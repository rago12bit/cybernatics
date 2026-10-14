import type { ReactNode } from "react";
import { SiteFooter } from "./SiteFooter";
import { ScrollReveal } from "./ScrollReveal";
import { SmoothScroll } from "./SmoothScroll";
import "./site-pages.css";

// The frame every public page shares: a heading block, the page's sections, the footer.
export function SitePage({
  eyebrow,
  title,
  lede,
  actions,
  children,
}: {
  eyebrow: string;
  title: string;
  lede: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="page">
      <SmoothScroll />
      <ScrollReveal />
      <header className="site-head">
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p className="lede">{lede}</p>
        {actions && <div className="hero-actions">{actions}</div>}
      </header>
      {children}
      <SiteFooter />
    </div>
  );
}

export function SiteSection({
  id,
  title,
  intro,
  children,
}: {
  id: string;
  title: string;
  intro?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="site-sec" id={id} aria-labelledby={`${id}-h`}>
      <div className="sec-head">
        <div className="stack">
          <h2 id={`${id}-h`}>{title}</h2>
          {intro && <p>{intro}</p>}
        </div>
      </div>
      {children}
    </section>
  );
}

/** One claim and where it lives, so a reader can check it. */
export function Fact({ label, children, src, status }: { label: string; children: ReactNode; src?: string; status?: "ok" | "open" }) {
  return (
    <div className="fact">
      <span className="label">{label}</span>
      {status && <span className={`tag ${status === "ok" ? "ok-tag" : "open-tag"}`}>{status === "ok" ? "In place" : "Not proven yet"}</span>}
      <p>{children}</p>
      {src && <span className="src">{src}</span>}
    </div>
  );
}
