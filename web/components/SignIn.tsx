"use client";

import Link from "next/link";
import { useEffect, useId, useState, type FormEvent } from "react";
import { ApiError, discoverSso, setToken, ssoStartUrl, verifyToken } from "@/lib/api";
import { SIGNIN_ERRORS, type SsoChoice } from "@/lib/identity";

/* Signing in (Week 75): with the organization's identity provider, found from a work email's
 * domain; or, for scripts, the shared server and organizations without single sign-on, by pasting
 * an API token, which stays in this tab only. */

export const SIGN_IN_TITLE = "Sign in · Bulwark";

export function SignIn({ next, error, onToken }: { next: string; error?: string | null; onToken?: () => void }) {
  const id = useId();
  const [email, setEmail] = useState("");
  const [choices, setChoices] = useState<SsoChoice[] | null>(null);
  const [looking, setLooking] = useState(false);
  const [lookError, setLookError] = useState<string | null>(null);
  const [tokenOpen, setTokenOpen] = useState(false);
  const [token, setTokenValue] = useState("");
  const [show, setShow] = useState(false);

  // Shown in place of any app page while signed out: the tab says so, not "Projects" or "App".
  useEffect(() => {
    const before = document.title;
    document.title = SIGN_IN_TITLE;
    return () => { document.title = before; };
  }, []);
  const [tokenError, setTokenError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function find(e: FormEvent) {
    e.preventDefault();
    setLooking(true); setLookError(null);
    try {
      const r = await discoverSso(email.trim());
      setChoices(r.providers);
      if (r.providers.length === 1) window.location.assign(ssoStartUrl(r.providers[0]!.id, next));
    } catch (err) {
      setLookError(err instanceof Error ? err.message : "Could not look that up.");
    } finally {
      setLooking(false);
    }
  }

  async function useToken(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setTokenError(null);
    try {
      await verifyToken(token.trim());
      setToken(token.trim());
      onToken?.();
    } catch (err) {
      setTokenError(err instanceof ApiError && err.status === 401 ? "That token was not accepted. Check it and try again." : err instanceof Error ? err.message : "Failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="gate-wrap">
      <div className="gate" aria-labelledby={`${id}-h`} role="region">
        <span className="eyebrow" id={`${id}-h`}>Sign in</span>
        <h1 className="h2">Sign in to Bulwark</h1>
        {error && <p className="error small" role="alert">{SIGNIN_ERRORS[error] ?? "That sign-in did not work. Start again."}</p>}
        <form onSubmit={find} className="gate-sso">
          <label htmlFor={`${id}-email`}>Work email</label>
          <input id={`${id}-email`} type="email" autoComplete="email" autoFocus required value={email}
            onChange={(e) => { setEmail(e.target.value); setChoices(null); }}
            aria-describedby={choices && choices.length === 0 ? `${id}-none` : undefined} />
          <button className="btn primary" disabled={looking || !email.trim()}>{looking ? "Looking…" : "Continue →"}</button>
        </form>
        {lookError && <p className="error small" role="alert">{lookError}</p>}
        {choices && choices.length === 0 && (
          <p id={`${id}-none`} className="small muted" role="status">
            That email&apos;s domain does not sign in with single sign-on here. Use an API token below, or ask your admin.
          </p>
        )}
        {choices && choices.length > 1 && (
          <ul className="gate-choices">
            {choices.map((c) => <li key={c.id}><a className="btn" href={ssoStartUrl(c.id, next)}>Continue with {c.name}</a></li>)}
          </ul>
        )}
        <details className="gate-token" open={tokenOpen || (choices !== null && choices.length === 0)}
          onToggle={(e) => setTokenOpen((e.target as HTMLDetailsElement).open)}>
          <summary>Use an API token instead</summary>
          <form onSubmit={useToken}>
            <p className="muted small">The server&apos;s token (<code>BULWARK_API_TOKEN</code>) or one you made. It stays in this browser tab only and is never put in a URL.</p>
            <label htmlFor={`${id}-token`}>API token</label>
            <div className="pw">
              <input id={`${id}-token`} type={show ? "text" : "password"} autoComplete="off" spellCheck={false} value={token}
                onChange={(e) => setTokenValue(e.target.value)} required
                aria-describedby={tokenError ? `${id}-token-err` : undefined} aria-invalid={tokenError ? true : undefined} />
              <button type="button" className="btn sm" onClick={() => setShow((s) => !s)} aria-pressed={show}>{show ? "Hide" : "Show"}</button>
            </div>
            {tokenError && <p id={`${id}-token-err`} className="error small" role="alert">{tokenError}</p>}
            <button className="btn" disabled={busy || !token.trim()}>{busy ? "Checking…" : "Use this token"}</button>
          </form>
        </details>
        <p className="small muted gate-alt">No server handy? <Link href="/sample">See the recorded scan</Link>, no sign-in needed.</p>
      </div>
    </div>
  );
}
