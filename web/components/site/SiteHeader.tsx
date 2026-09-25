"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { clearToken, getToken } from "@/lib/api";
import { BrandMark } from "./graphics";

const LINKS = [
  { href: "/about#product", label: "Product", id: "product" },
  { href: "/about#results", label: "Results", id: "results" },
  { href: "/about#scanners", label: "Scanners", id: "scanners" },
  { href: "/", label: "Sample scan" },
  { href: "/app", label: "App" },
];

export function SiteHeader() {
  const path = usePathname();
  const router = useRouter();
  const [menu, setMenu] = useState(false);
  const [signedIn, setSignedIn] = useState(false);
  const [active, setActive] = useState("product");
  const onLanding = path === "/about";
  const inApp = path.startsWith("/app") || path.startsWith("/scans");

  useEffect(() => { setSignedIn(Boolean(getToken())); setMenu(false); }, [path]);

  // Highlight the landing section being read (scroll spy).
  useEffect(() => {
    if (!onLanding || typeof IntersectionObserver === "undefined") return; // progressive enhancement
    const els = ["product", "results", "scanners"].map((id) => document.getElementById(id)).filter((e): e is HTMLElement => !!e);
    const io = new IntersectionObserver(
      (entries) => entries.forEach((e) => e.isIntersecting && setActive(e.target.id)),
      { rootMargin: "-35% 0px -55% 0px" },
    );
    els.forEach((e) => io.observe(e));
    return () => io.disconnect();
  }, [onLanding]);

  useEffect(() => {
    if (!menu) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setMenu(false);
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [menu]);

  const current = (l: (typeof LINKS)[number]) =>
    l.id ? (onLanding && active === l.id ? "location" : undefined) : (l.href === "/" ? path === "/" : path.startsWith(l.href) || (l.href === "/app" && inApp)) ? "page" : undefined;

  const signOut = () => { clearToken(); setSignedIn(false); setMenu(false); router.push("/"); };

  const links = LINKS.map((l) => (
    <Link key={l.href} href={l.href} aria-current={current(l)} onClick={() => setMenu(false)}>{l.label}</Link>
  ));

  return (
    <header className="top">
      <div className="top-inner">
        <Link href="/" className="brand" aria-label="Bulwark home"><BrandMark />Bulwark</Link>
        <nav aria-label="Primary" className="nav-desktop">{links}</nav>
        <span className="spacer" />
        {signedIn && inApp && <button type="button" className="btn sm" onClick={signOut}>Sign out</button>}
        {!inApp && <Link href="/app" className="btn primary sm nav-cta">Open app →</Link>}
        <button type="button" className="btn sm menu-btn" aria-expanded={menu} aria-controls="mobile-nav" onClick={() => setMenu((m) => !m)}>{menu ? "Close" : "Menu"}</button>
      </div>
      <nav id="mobile-nav" aria-label="Mobile" className="nav-mobile" hidden={!menu}>
        {links}
        {signedIn && <button type="button" className="linkbtn" onClick={signOut}>Sign out</button>}
      </nav>
    </header>
  );
}
