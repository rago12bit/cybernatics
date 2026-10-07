"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { clearToken, getToken, onAuthChange } from "@/lib/api";
import { APP_HREF, APP_NAV, DEMO_ONLY } from "@/lib/site";
import { APP_LINKS, InboxLink, MORE_LINKS, MoreMenu, isCurrent, useUnread } from "./AppNav";
import { BrandMark } from "./graphics";

const LINKS = [
  { href: "/", label: "Home", id: "product" },
  { href: "/#results", label: "Results", id: "results" },
  { href: "/#scanners", label: "Scanners", id: "scanners" },
  { href: "/sample", label: "Sample scan" },
  { href: APP_HREF, label: APP_NAV },
];

export function SiteHeader() {
  const path = usePathname();
  const router = useRouter();
  const [menu, setMenu] = useState(false);
  const [signedIn, setSignedIn] = useState(false);
  const [active, setActive] = useState("product");
  const onLanding = path === "/";
  const inApp = path.startsWith("/app") || path.startsWith("/scans");
  // Signed in to the app, the header carries the app's own sections instead of the site's.
  const appMode = inApp && signedIn && !DEMO_ONLY;
  const unread = useUnread(appMode);

  useEffect(() => { setMenu(false); }, [path]);
  useEffect(() => {
    const sync = () => setSignedIn(Boolean(getToken()));
    sync();
    return onAuthChange(sync);
  }, [path]);

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

  // Arriving from another page (e.g. Home -> Scanners) the router changes the URL but doesn't
  // scroll to the section: the landing content mounts after it looks for the target. Scroll to it
  // ourselves, waiting briefly for it to exist.
  useEffect(() => {
    if (!onLanding) return;
    const id = decodeURIComponent(window.location.hash.slice(1));
    if (!id) return;
    let timer: ReturnType<typeof setTimeout>;
    let stopped = false;
    const stop = () => { stopped = true; };
    const opts = { passive: true } as const;
    window.addEventListener("wheel", stop, opts);
    window.addEventListener("touchstart", stop, opts);
    window.addEventListener("keydown", stop);
    const started = performance.now();
    // The page keeps growing for a moment after it mounts (sections reveal, counters render), so
    // a single scroll lands short of the target. Re-align until the section sits where the sticky
    // header leaves room for it, or the reader scrolls on their own.
    const align = () => {
      if (stopped || performance.now() - started > 3000) return;
      const el = document.getElementById(id);
      if (el) {
        setActive(id);
        const want = parseFloat(getComputedStyle(el).scrollMarginTop) || 0;
        if (Math.abs(el.getBoundingClientRect().top - want) > 2) {
          el.scrollIntoView({ block: "start", behavior: "instant" });
        }
      }
      timer = setTimeout(align, 100);
    };
    align();
    return () => {
      clearTimeout(timer);
      window.removeEventListener("wheel", stop);
      window.removeEventListener("touchstart", stop);
      window.removeEventListener("keydown", stop);
    };
  }, [onLanding, path]);

  useEffect(() => {
    if (!menu) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setMenu(false);
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [menu]);

  // Home is the top of the landing page, so it is the current *page* while that section is in view;
  // Results and Scanners are sections of it ("location"). Sample scan and App are pages.
  const current = (l: (typeof LINKS)[number]) => {
    if (l.href === "/") return path === "/" && active === "product" ? "page" : undefined;
    if (l.id) return onLanding && active === l.id ? "location" : undefined;
    return path.startsWith(l.href) || (l.href === "/app" && inApp) ? "page" : undefined;
  };

  const signOut = () => { clearToken(); setSignedIn(false); setMenu(false); router.push("/"); };

  const links = LINKS.map((l) => (
    <Link key={l.href} href={l.href} aria-current={current(l)} onClick={() => { setMenu(false); if (l.id) setActive(l.id); }}>{l.label}</Link>
  ));
  const appLink = (l: { href: string; label: string }) => (
    <Link key={l.href} href={l.href} aria-current={isCurrent(path, l.href) ? "page" : undefined} onClick={() => setMenu(false)}>{l.label}</Link>
  );
  const appDesktop = [...APP_LINKS.slice(0, 2).map(appLink), <InboxLink key="inbox" path={path} unread={unread} />, ...APP_LINKS.slice(2).map(appLink)];
  const appMobile = [...APP_LINKS.slice(0, 2).map(appLink), <InboxLink key="inbox" path={path} unread={unread} onClick={() => setMenu(false)} />, ...APP_LINKS.slice(2).map(appLink), ...MORE_LINKS.map(appLink)];

  return (
    <header className="top">
      <div className="top-inner">
        <Link href="/" className="brand" aria-label="Bulwark home"><BrandMark />Bulwark</Link>
        {appMode ? (
          <nav aria-label="App" className="nav-desktop nav-app">{appDesktop}<MoreMenu path={path} /></nav>
        ) : (
          <nav aria-label="Primary" className="nav-desktop">{links}</nav>
        )}
        <span className="spacer" />
        {signedIn && inApp && <button type="button" className="btn sm" onClick={signOut}>Sign out</button>}
        {!inApp && <Link href={APP_HREF} className="btn primary sm nav-cta">{DEMO_ONLY ? "Run it yourself →" : "Open app →"}</Link>}
        <button type="button" className="btn sm menu-btn" aria-expanded={menu} aria-controls="mobile-nav" onClick={() => setMenu((m) => !m)}>{menu ? "Close" : "Menu"}</button>
      </div>
      <nav id="mobile-nav" aria-label="Mobile" className="nav-mobile" hidden={!menu}>
        {appMode ? appMobile : links}
        {signedIn && <button type="button" className="linkbtn" onClick={signOut}>Sign out</button>}
      </nav>
    </header>
  );
}
