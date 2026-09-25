"use client";

import Link from "next/link";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { ApiError, clearToken, getToken, onAuthChange, setToken, verifyToken } from "@/lib/api";

export function TokenGate({ children }: { children: ReactNode }) {
  const [state, setState] = useState<"checking" | "need" | "ok">("checking");
  const [value, setValue] = useState("");
  const [show, setShow] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const t = getToken();
    if (!t) return setState("need");
    verifyToken(t).then(
      () => setState("ok"),
      (e) => {
        if (e instanceof ApiError && e.status === 401) clearToken();
        else setError(e instanceof Error ? e.message : "Cannot verify token");
        setState("need");
      },
    );
  }, []);

  // Signing out (or a token the server rejected) anywhere in this tab returns to the sign-in screen.
  useEffect(() => onAuthChange(() => { if (!getToken()) setState((cur) => (cur === "ok" ? "need" : cur)); }), []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await verifyToken(value.trim());
      setToken(value.trim());
      setState("ok");
    } catch (err) {
      setError(err instanceof ApiError && err.status === 401 ? "That token was not accepted. Check it and try again." : err instanceof Error ? err.message : "Failed");
    } finally {
      setBusy(false);
    }
  }

  if (state === "checking") return <div className="state-page compact" role="status" aria-live="polite"><span className="eyebrow">Connecting</span><span className="sk sk-l" /></div>;
  if (state === "ok") return <>{children}</>;
  return (
    <div className="gate-wrap">
      <form className="gate" onSubmit={submit} aria-labelledby="gate-h">
        <span className="eyebrow" id="gate-h">Sign in</span>
        <h1 className="h2">Connect to your Bulwark server</h1>
        <p className="muted small">Paste the API token from your server&apos;s <code>.env</code> file (<code>BULWARK_API_TOKEN</code>). It stays in this browser tab only and is never put in a URL.</p>
        <label htmlFor="token">API token</label>
        <div className="pw">
          <input id="token" type={show ? "text" : "password"} autoComplete="off" autoFocus spellCheck={false} value={value} onChange={(e) => setValue(e.target.value)} required aria-describedby={error ? "token-err" : undefined} aria-invalid={error ? true : undefined} />
          <button type="button" className="btn sm" onClick={() => setShow((s) => !s)} aria-pressed={show}>{show ? "Hide" : "Show"}</button>
        </div>
        {error && <p id="token-err" className="error small" role="alert">{error}</p>}
        <button className="btn primary" disabled={busy || !value.trim()}>{busy ? "Checking…" : "Continue →"}</button>
        <p className="small muted gate-alt">No server handy? <Link href="/">Explore a sample scan</Link>, no token needed.</p>
      </form>
    </div>
  );
}
