"use client";

import { useEffect, useState, type ReactNode } from "react";
import { ApiError, clearToken, getSession, getToken, hasSession, onAuthChange, verifyToken } from "@/lib/api";
import { SignIn } from "./SignIn";

/* The app's pages need someone signed in: a browser session from the organization's identity
 * provider (Week 75), or a pasted API token. Signing out anywhere in the tab returns here. */
export function TokenGate({ children }: { children: ReactNode }) {
  const [state, setState] = useState<"checking" | "need" | "ok">("checking");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const t = getToken();
    if (t) {
      verifyToken(t).then(
        () => setState("ok"),
        (e) => {
          if (e instanceof ApiError && e.status === 401) clearToken();
          else setError(e instanceof Error ? e.message : "Cannot verify token");
          getSession().then((s) => setState(s ? "ok" : "need"));
        },
      );
      return;
    }
    getSession().then((s) => setState(s ? "ok" : "need"));
  }, []);

  useEffect(() => onAuthChange(() => {
    if (!getToken() && !hasSession()) setState((cur) => (cur === "ok" ? "need" : cur));
  }), []);

  if (state === "checking") return <div className="state-page compact" role="status" aria-live="polite"><span className="eyebrow">Connecting</span><span className="sk sk-l" /></div>;
  if (state === "ok") return <>{children}</>;
  const here = typeof window === "undefined" ? "/app" : `${window.location.pathname}${window.location.search}`;
  return (
    <>
      {error && <p className="error small" role="alert">{error}</p>}
      <SignIn next={here} onToken={() => setState("ok")} />
    </>
  );
}
