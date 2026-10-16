"use client";

import Link from "next/link";
import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { ApiError, createGitScan, getSession, getToken, onAuthChange, type WebSession } from "@/lib/api";
import { githubRepo } from "@/lib/github";
import { goTo } from "@/lib/navigate";
import { DEMO_ONLY } from "@/lib/site";
import { TOOLS } from "@/lib/types";

// The repository typed before signing in, so it is still there on the way back. Per tab only.
const PENDING_KEY = "bulwark.pendingRepo";
const remember = (v: string) => { try { sessionStorage.setItem(PENDING_KEY, v); } catch { /* storage off: retype it */ } };
const recall = () => { try { const v = sessionStorage.getItem(PENDING_KEY); sessionStorage.removeItem(PENDING_KEY); return v; } catch { return null; } };

type Who = { kind: "checking" } | { kind: "out" } | { kind: "token" } | { kind: "session"; session: WebSession };

/**
 * The home page's "scan a GitHub repository": type owner/repo (or paste any link to it), sign in if
 * you have not, and the scan starts with the default scanners. The sample site (DEMO_ONLY) has no
 * API, so there it explains where to run it instead. It moves on with a full page load (sign-in may
 * leave for the identity provider anyway), so the home page needs no app router and renders anywhere.
 */
export function RepoScan() {
  const id = useId();
  const [value, setValue] = useState("");
  const [who, setWho] = useState<Who>(DEMO_ONLY ? { kind: "out" } : { kind: "checking" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const field = useRef<HTMLInputElement>(null);
  const repo = githubRepo(value);
  const ok = repo !== null && "url" in repo ? repo : null;

  useEffect(() => {
    // Typed before the page finished loading: the box shows it, but no change event reached us.
    const pending = recall() ?? field.current?.value;
    if (pending) setValue(pending);
    // Back from signing in (/#scan-repo): the browser's own jump to the anchor happens before the
    // home page's sections are laid out, so land here once they are.
    let raf = 0;
    if (window.location.hash === "#scan-repo") {
      raf = requestAnimationFrame(() => document.getElementById("scan-repo")?.scrollIntoView({ block: "start" }));
    }
    if (DEMO_ONLY) return () => cancelAnimationFrame(raf);
    const check = () => {
      if (getToken()) return setWho({ kind: "token" });
      getSession().then((s) => setWho(s ? { kind: "session", session: s } : { kind: "out" }));
    };
    check();
    const off = onAuthChange(check);
    return () => { cancelAnimationFrame(raf); off(); };
  }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!ok) return;
    if (DEMO_ONLY) return goTo("/self-host");
    // Pressed before the sign-in check came back: wait for it rather than greying the button out.
    const out = who.kind === "out" || (who.kind === "checking" && !getToken() && !(await getSession()));
    if (out) {
      remember(ok.slug);
      return goTo(`/signin?next=${encodeURIComponent("/#scan-repo")}`);
    }
    setBusy(true);
    setError(null);
    try {
      const created = await createGitScan(ok.url, [...TOOLS]);
      goTo(`/scans/${created.id}`);
    } catch (err) {
      setError(err instanceof ApiError && err.status === 401 ? "Your sign-in has expired. Sign in again to scan." : err instanceof Error ? err.message : "Could not start the scan.");
      setBusy(false);
    }
  }

  const signedIn = who.kind === "token" || who.kind === "session";
  const action = DEMO_ONLY ? "Run it yourself to scan →" : busy ? "Starting…" : signedIn ? "Scan this repository →" : "Sign in and scan →";
  const hint = repo && "error" in repo ? repo.error : null;

  return (
    <section className="section" id="scan-repo" aria-labelledby={`${id}-h`}>
      <div className="repo-scan">
        <div className="stack reveal-me">
          <span className="eyebrow">Scan your code</span>
          <h2 id={`${id}-h`}>Scan a GitHub repository</h2>
          <p className="lede">
            Give it any public repository. Bulwark clones the default branch into a sandbox, runs the five default
            scanners with no network, and merges what they find into one report.
          </p>
          <ol className="repo-steps">
            <li className={signedIn ? "done" : undefined}>Sign in with your organization&apos;s single sign-on, or an API token.</li>
            <li className={ok ? "done" : undefined}>Type the repository, or paste any link to it.</li>
            <li>Watch each scanner report in, then triage the merged Issues.</li>
          </ol>
        </div>
        <form className="repo-form reveal-me" onSubmit={submit} aria-describedby={`${id}-help`}>
          {who.kind === "session" && (
            <p className="repo-who" role="status">
              <span>Signed in as <b>{who.session.user.name || who.session.user.email}</b></span>
              <Link href="/app" className="small">Open the app →</Link>
            </p>
          )}
          {who.kind === "token" && (
            <p className="repo-who" role="status"><span>Signed in with an <b>API token</b> in this tab</span><Link href="/app" className="small">Open the app →</Link></p>
          )}
          <label htmlFor={`${id}-repo`}>GitHub repository</label>
          <div className="repo-field">
            {!/^\s*(https?:\/\/|(www\.)?[a-z0-9-]+\.[a-z]{2,}\/)/i.test(value) && <span className="prefix" aria-hidden="true">github.com/</span>}
            <input ref={field} id={`${id}-repo`} name="repo" type="text" inputMode="url" autoComplete="off" autoCapitalize="off" spellCheck={false}
              placeholder="owner/repository" value={value} onChange={(e) => { setValue(e.target.value); setError(null); }}
              aria-invalid={hint ? true : undefined} aria-describedby={`${id}-help`} />
          </div>
          <p id={`${id}-help`} className={hint ? "error small" : "muted small"} role={hint ? "alert" : undefined}>
            {hint ?? (ok ? `Will scan ${ok.url}` : "For example OWASP/NodeGoat, or paste https://github.com/OWASP/NodeGoat.")}
          </p>
          {DEMO_ONLY && (
            <p className="small muted">This sample site has no scanner behind it. Run Bulwark on your own machine and this box scans for real.</p>
          )}
          {error && <p className="error small" role="alert">{error}</p>}
          <div className="repo-actions">
            <button className="btn primary" disabled={!ok || busy} aria-describedby={`${id}-why`}>{action}</button>
            {!DEMO_ONLY && <Link href="/app/scan" className="small muted">Upload an archive or choose scanners</Link>}
          </div>
          <p id={`${id}-why`} className="small muted repo-why">
            {!ok ? (hint ? "Fix the repository above to scan it." : "Type a repository above to scan it.")
              : DEMO_ONLY ? "Scanning needs Bulwark running on your own machine."
              : signedIn ? "Starts with the five default scanners."
              : "You sign in first. The scan starts as soon as you are back here."}
          </p>
        </form>
      </div>
    </section>
  );
}
