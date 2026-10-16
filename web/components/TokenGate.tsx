"use client";

import { useEffect, useState, type ReactNode } from "react";
import { API_URL, ApiError, clearToken, getSession, getToken, hasSession, onAuthChange, verifyToken } from "@/lib/api";
import { SignIn } from "./SignIn";

const SLOW_MS = 5000; // then say what is being waited on, and offer to try again

/* The app's pages need someone signed in: a browser session from the organization's identity
 * provider (Week 75), or a pasted API token. Signing out anywhere in the tab returns here. */
export function TokenGate({ children }: { children: ReactNode }) {
  const [state, setState] = useState<"checking" | "need" | "ok">("checking");
  const [error, setError] = useState<string | null>(null);
  const [slow, setSlow] = useState(false);

  useEffect(() => {
    if (state !== "checking") return;
    const t = window.setTimeout(() => setSlow(true), SLOW_MS);
    return () => clearTimeout(t);
  }, [state]);

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

  if (state === "checking") {
    return (
      <div className="state-page compact" role="status" aria-live="polite">
        <span className="eyebrow">Connecting</span>
        {slow ? (
          <>
            <p className="muted">The Bulwark API at <code>{API_URL}</code> has not answered yet. It may still be starting, or it may not be running.</p>
            <button type="button" className="btn sm" onClick={() => window.location.reload()}>Try again</button>
          </>
        ) : <span className="sk sk-l" />}
      </div>
    );
  }
  if (state === "ok") return <>{children}</>;
  const here = typeof window === "undefined" ? "/app" : `${window.location.pathname}${window.location.search}`;
  return (
    <>
      {error && <p className="error small" role="alert">{error}</p>}
      <SignIn next={here} onToken={() => setState("ok")} />
    </>
  );
}
