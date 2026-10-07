"use client";

import { useCallback, useEffect, useId, useState, type FormEvent } from "react";
import { ApiError, createMyToken, listMyTokens, revokeMyToken } from "@/lib/api";
import { TOKEN_SCOPES, type TokenView } from "@/lib/identity";
import { Button } from "@/design-system/primitives/Button";
import "./identity.css";

/* My API tokens (Week 75): for CI and scripts. A token acts as me, within the scopes it was given
 * and my role at the time it is used -- so it can never do more than I can. Shown once. */

function message(e: unknown, fallback: string): string {
  if (e instanceof ApiError) return (e.data as { message?: string } | undefined)?.message ?? e.message;
  return fallback;
}

export function MyTokens() {
  const id = useId();
  const [tokens, setTokens] = useState<TokenView[] | null>(null);
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<string[]>(["scans:read"]);
  const [days, setDays] = useState(90);
  const [fresh, setFresh] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => { listMyTokens().then(setTokens, (e) => setError(message(e, "Could not load your tokens."))); }, []);
  useEffect(load, [load]);
  async function make(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try { const t = await createMyToken({ name: name.trim(), scopes, days }); setFresh(t.token); setName(""); load(); }
    catch (err) { setError(message(err, "Could not make a token.")); }
  }
  async function revoke(t: TokenView) {
    try { await revokeMyToken(t.id); load(); } catch (err) { setError(message(err, "Could not revoke it.")); }
  }
  const live = tokens?.filter((t) => !t.revoked_at) ?? [];
  return (
    <div className="idn">
      <p className="idn-muted">A token acts as you, within the scopes you give it and your role when it is used: it can never do more than you can, and it stops working if you are turned off.</p>
      <form onSubmit={make} className="idn-form idn-narrow">
        <label htmlFor={`${id}-n`}>Name</label>
        <input id={`${id}-n`} value={name} onChange={(e) => setName(e.target.value)} placeholder="CI pipeline" required />
        <fieldset className="idn-kind">
          <legend>It may</legend>
          {TOKEN_SCOPES.map(([s, label]) => (
            <label key={s} className="idn-check"><input type="checkbox" checked={scopes.includes(s)} onChange={(e) => setScopes((cur) => (e.target.checked ? [...cur, s] : cur.filter((x) => x !== s)))} />{label} <code>{s}</code></label>
          ))}
        </fieldset>
        <label htmlFor={`${id}-d`}>Expires in (days)</label>
        <input id={`${id}-d`} type="number" min={1} max={365} value={days} onChange={(e) => setDays(Number(e.target.value))} />
        <div className="idn-actions"><Button type="submit" variant="primary" disabled={!name.trim() || scopes.length === 0}>Make a token</Button></div>
      </form>
      {fresh && (
        <div className="idn-fresh" role="status">
          <label htmlFor={`${id}-t`}>Your token. Copy it now: it is shown only once.</label>
          <input id={`${id}-t`} readOnly value={fresh} onFocus={(e) => e.currentTarget.select()} />
          <Button type="button" onClick={() => setFresh(null)}>I have copied it</Button>
        </div>
      )}
      {error && <p role="alert" className="idn-error">{error}</p>}
      {tokens && live.length === 0 && <p className="idn-empty">No tokens.</p>}
      {live.length > 0 && (
        <ul className="idn-overrides">
          {live.map((t) => (
            <li key={t.id}><strong>{t.name}</strong> <span className="idn-muted">{t.prefix}… · {(t.scopes ?? []).join(", ")} · expires {t.expires_at?.slice(0, 10) ?? "never"} · last used {t.last_used_at?.slice(0, 10) ?? "never"}</span>{" "}
              <button type="button" className="idn-link" onClick={() => revoke(t)} aria-label={`Revoke ${t.name}`}>Revoke</button></li>
          ))}
        </ul>
      )}
    </div>
  );
}
