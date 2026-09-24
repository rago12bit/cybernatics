"use client";

import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { ApiError, clearToken, getToken, setToken, verifyToken } from "@/lib/api";

export function TokenGate({ children }: { children: ReactNode }) {
  const [state, setState] = useState<"checking" | "need" | "ok">("checking");
  const [value, setValue] = useState("");
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

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await verifyToken(value.trim());
      setToken(value.trim());
      setState("ok");
    } catch (err) {
      setError(err instanceof ApiError && err.status === 401 ? "That token was not accepted." : err instanceof Error ? err.message : "Failed");
    } finally {
      setBusy(false);
    }
  }

  if (state === "checking") return <p className="cell muted" role="status">Connecting…</p>;
  if (state === "ok") return <>{children}</>;
  return (
    <form className="gate" onSubmit={submit}>
      <span className="eyebrow">Sign in</span>
      <p className="muted">
        Enter your API token (<code>BULWARK_API_TOKEN</code> from <code>.env</code>). It is kept only for
        this browser tab.
      </p>
      <label htmlFor="token">API token</label>
      <input id="token" type="password" autoComplete="off" value={value} onChange={(e) => setValue(e.target.value)} required />
      {error && <p className="error" role="alert">{error}</p>}
      <button className="btn primary" disabled={busy || !value.trim()}>{busy ? "Checking…" : "Continue →"}</button>
    </form>
  );
}
